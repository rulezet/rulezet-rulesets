rule TTP_XOR_WriteProcessMemory_ed58 {
  strings:
    $key_ed58 = { ba 2a [2] 88 08 [2] 8e 3d [2] a0 3d [2] 9f 21 }

  condition:
    any of them
}