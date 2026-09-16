rule TTP_XOR_WriteProcessMemory_dd67 {
  strings:
    $key_dd67 = { 8a 15 [2] b8 37 [2] be 02 [2] 90 02 [2] af 1e }

  condition:
    any of them
}