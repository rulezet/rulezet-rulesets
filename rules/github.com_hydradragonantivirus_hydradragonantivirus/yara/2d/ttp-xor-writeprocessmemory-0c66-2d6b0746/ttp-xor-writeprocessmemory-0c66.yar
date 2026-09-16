rule TTP_XOR_WriteProcessMemory_0c66 {
  strings:
    $key_0c66 = { 5b 14 [2] 69 36 [2] 6f 03 [2] 41 03 [2] 7e 1f }

  condition:
    any of them
}