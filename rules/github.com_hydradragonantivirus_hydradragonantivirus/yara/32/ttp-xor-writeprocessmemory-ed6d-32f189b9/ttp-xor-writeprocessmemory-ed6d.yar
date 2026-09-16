rule TTP_XOR_WriteProcessMemory_ed6d {
  strings:
    $key_ed6d = { ba 1f [2] 88 3d [2] 8e 08 [2] a0 08 [2] 9f 14 }

  condition:
    any of them
}