rule TTP_XOR_WriteProcessMemory_2fe6 {
  strings:
    $key_2fe6 = { 78 94 [2] 4a b6 [2] 4c 83 [2] 62 83 [2] 5d 9f }

  condition:
    any of them
}