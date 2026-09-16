rule TTP_XOR_WriteProcessMemory_ed3d {
  strings:
    $key_ed3d = { ba 4f [2] 88 6d [2] 8e 58 [2] a0 58 [2] 9f 44 }

  condition:
    any of them
}