rule TTP_XOR_WriteProcessMemory_dd47 {
  strings:
    $key_dd47 = { 8a 35 [2] b8 17 [2] be 22 [2] 90 22 [2] af 3e }

  condition:
    any of them
}