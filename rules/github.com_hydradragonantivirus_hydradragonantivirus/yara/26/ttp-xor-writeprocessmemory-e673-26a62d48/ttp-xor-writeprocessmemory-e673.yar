rule TTP_XOR_WriteProcessMemory_e673 {
  strings:
    $key_e673 = { b1 01 [2] 83 23 [2] 85 16 [2] ab 16 [2] 94 0a }

  condition:
    any of them
}