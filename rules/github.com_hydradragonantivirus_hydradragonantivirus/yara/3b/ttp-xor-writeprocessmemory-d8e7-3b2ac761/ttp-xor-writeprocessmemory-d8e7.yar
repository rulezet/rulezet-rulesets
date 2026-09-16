rule TTP_XOR_WriteProcessMemory_d8e7 {
  strings:
    $key_d8e7 = { 8f 95 [2] bd b7 [2] bb 82 [2] 95 82 [2] aa 9e }

  condition:
    any of them
}