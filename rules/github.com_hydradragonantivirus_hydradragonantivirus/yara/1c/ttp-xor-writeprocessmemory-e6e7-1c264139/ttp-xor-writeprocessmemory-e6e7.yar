rule TTP_XOR_WriteProcessMemory_e6e7 {
  strings:
    $key_e6e7 = { b1 95 [2] 83 b7 [2] 85 82 [2] ab 82 [2] 94 9e }

  condition:
    any of them
}