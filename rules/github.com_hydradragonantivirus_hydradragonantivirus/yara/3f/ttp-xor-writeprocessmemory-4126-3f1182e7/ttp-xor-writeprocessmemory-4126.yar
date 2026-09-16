rule TTP_XOR_WriteProcessMemory_4126 {
  strings:
    $key_4126 = { 16 54 [2] 24 76 [2] 22 43 [2] 0c 43 [2] 33 5f }

  condition:
    any of them
}