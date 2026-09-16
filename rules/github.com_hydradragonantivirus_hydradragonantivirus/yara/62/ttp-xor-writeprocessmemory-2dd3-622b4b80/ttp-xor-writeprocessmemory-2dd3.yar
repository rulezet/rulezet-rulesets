rule TTP_XOR_WriteProcessMemory_2dd3 {
  strings:
    $key_2dd3 = { 7a a1 [2] 48 83 [2] 4e b6 [2] 60 b6 [2] 5f aa }

  condition:
    any of them
}