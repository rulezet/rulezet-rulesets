rule TTP_XOR_WriteProcessMemory_e476 {
  strings:
    $key_e476 = { b3 04 [2] 81 26 [2] 87 13 [2] a9 13 [2] 96 0f }

  condition:
    any of them
}