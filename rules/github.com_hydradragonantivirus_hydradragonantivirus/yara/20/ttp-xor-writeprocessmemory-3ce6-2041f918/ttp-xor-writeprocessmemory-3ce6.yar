rule TTP_XOR_WriteProcessMemory_3ce6 {
  strings:
    $key_3ce6 = { 6b 94 [2] 59 b6 [2] 5f 83 [2] 71 83 [2] 4e 9f }

  condition:
    any of them
}