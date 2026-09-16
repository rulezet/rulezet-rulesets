rule TTP_XOR_WriteProcessMemory_fc91 {
  strings:
    $key_fc91 = { ab e3 [2] 99 c1 [2] 9f f4 [2] b1 f4 [2] 8e e8 }

  condition:
    any of them
}