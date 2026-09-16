rule TTP_XOR_WriteProcessMemory_6de6 {
  strings:
    $key_6de6 = { 3a 94 [2] 08 b6 [2] 0e 83 [2] 20 83 [2] 1f 9f }

  condition:
    any of them
}