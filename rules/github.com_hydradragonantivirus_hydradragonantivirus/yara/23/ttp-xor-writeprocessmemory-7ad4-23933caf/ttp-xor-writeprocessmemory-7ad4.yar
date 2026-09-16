rule TTP_XOR_WriteProcessMemory_7ad4 {
  strings:
    $key_7ad4 = { 2d a6 [2] 1f 84 [2] 19 b1 [2] 37 b1 [2] 08 ad }

  condition:
    any of them
}