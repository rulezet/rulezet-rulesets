rule TTP_XOR_WriteProcessMemory_e640 {
  strings:
    $key_e640 = { b1 32 [2] 83 10 [2] 85 25 [2] ab 25 [2] 94 39 }

  condition:
    any of them
}