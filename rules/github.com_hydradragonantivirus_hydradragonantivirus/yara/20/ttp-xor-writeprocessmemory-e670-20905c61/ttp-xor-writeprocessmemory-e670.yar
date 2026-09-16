rule TTP_XOR_WriteProcessMemory_e670 {
  strings:
    $key_e670 = { b1 02 [2] 83 20 [2] 85 15 [2] ab 15 [2] 94 09 }

  condition:
    any of them
}