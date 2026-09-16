rule TTP_XOR_WriteProcessMemory_2de6 {
  strings:
    $key_2de6 = { 7a 94 [2] 48 b6 [2] 4e 83 [2] 60 83 [2] 5f 9f }

  condition:
    any of them
}