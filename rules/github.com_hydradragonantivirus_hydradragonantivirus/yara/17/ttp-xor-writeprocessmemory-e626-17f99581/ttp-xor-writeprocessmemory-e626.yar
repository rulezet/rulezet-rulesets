rule TTP_XOR_WriteProcessMemory_e626 {
  strings:
    $key_e626 = { b1 54 [2] 83 76 [2] 85 43 [2] ab 43 [2] 94 5f }

  condition:
    any of them
}