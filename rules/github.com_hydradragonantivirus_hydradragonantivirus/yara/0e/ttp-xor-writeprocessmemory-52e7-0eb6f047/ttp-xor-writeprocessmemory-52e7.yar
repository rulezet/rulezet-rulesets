rule TTP_XOR_WriteProcessMemory_52e7 {
  strings:
    $key_52e7 = { 05 95 [2] 37 b7 [2] 31 82 [2] 1f 82 [2] 20 9e }

  condition:
    any of them
}