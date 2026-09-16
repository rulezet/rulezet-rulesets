rule TTP_XOR_WriteProcessMemory_2ab4 {
  strings:
    $key_2ab4 = { 7d c6 [2] 4f e4 [2] 49 d1 [2] 67 d1 [2] 58 cd }

  condition:
    any of them
}