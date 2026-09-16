rule TTP_XOR_WriteProcessMemory_e617 {
  strings:
    $key_e617 = { b1 65 [2] 83 47 [2] 85 72 [2] ab 72 [2] 94 6e }

  condition:
    any of them
}