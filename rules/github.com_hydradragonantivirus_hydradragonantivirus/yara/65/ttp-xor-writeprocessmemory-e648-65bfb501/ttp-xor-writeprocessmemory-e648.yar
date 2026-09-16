rule TTP_XOR_WriteProcessMemory_e648 {
  strings:
    $key_e648 = { b1 3a [2] 83 18 [2] 85 2d [2] ab 2d [2] 94 31 }

  condition:
    any of them
}