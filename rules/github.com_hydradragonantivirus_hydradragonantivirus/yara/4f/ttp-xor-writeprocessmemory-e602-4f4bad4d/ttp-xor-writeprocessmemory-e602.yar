rule TTP_XOR_WriteProcessMemory_e602 {
  strings:
    $key_e602 = { b1 70 [2] 83 52 [2] 85 67 [2] ab 67 [2] 94 7b }

  condition:
    any of them
}