rule TTP_XOR_WriteProcessMemory_2fe2 {
  strings:
    $key_2fe2 = { 78 90 [2] 4a b2 [2] 4c 87 [2] 62 87 [2] 5d 9b }

  condition:
    any of them
}