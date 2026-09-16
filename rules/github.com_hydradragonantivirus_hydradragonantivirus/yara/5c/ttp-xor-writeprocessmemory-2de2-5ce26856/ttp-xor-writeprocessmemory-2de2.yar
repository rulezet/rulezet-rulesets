rule TTP_XOR_WriteProcessMemory_2de2 {
  strings:
    $key_2de2 = { 7a 90 [2] 48 b2 [2] 4e 87 [2] 60 87 [2] 5f 9b }

  condition:
    any of them
}