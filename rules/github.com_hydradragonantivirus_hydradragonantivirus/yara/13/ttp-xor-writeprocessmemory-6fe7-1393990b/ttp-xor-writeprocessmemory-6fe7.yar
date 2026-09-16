rule TTP_XOR_WriteProcessMemory_6fe7 {
  strings:
    $key_6fe7 = { 38 95 [2] 0a b7 [2] 0c 82 [2] 22 82 [2] 1d 9e }

  condition:
    any of them
}