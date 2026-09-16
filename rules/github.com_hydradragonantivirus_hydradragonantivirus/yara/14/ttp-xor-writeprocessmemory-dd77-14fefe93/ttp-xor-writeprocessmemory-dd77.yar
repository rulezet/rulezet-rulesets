rule TTP_XOR_WriteProcessMemory_dd77 {
  strings:
    $key_dd77 = { 8a 05 [2] b8 27 [2] be 12 [2] 90 12 [2] af 0e }

  condition:
    any of them
}