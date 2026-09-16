rule TTP_XOR_WriteProcessMemory_6d73 {
  strings:
    $key_6d73 = { 3a 01 [2] 08 23 [2] 0e 16 [2] 20 16 [2] 1f 0a }

  condition:
    any of them
}