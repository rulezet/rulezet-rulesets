rule TTP_XOR_WriteProcessMemory_e6c1 {
  strings:
    $key_e6c1 = { b1 b3 [2] 83 91 [2] 85 a4 [2] ab a4 [2] 94 b8 }

  condition:
    any of them
}