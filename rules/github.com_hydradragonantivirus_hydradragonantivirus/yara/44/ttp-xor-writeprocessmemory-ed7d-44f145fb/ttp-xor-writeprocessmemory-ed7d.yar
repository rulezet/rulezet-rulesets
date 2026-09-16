rule TTP_XOR_WriteProcessMemory_ed7d {
  strings:
    $key_ed7d = { ba 0f [2] 88 2d [2] 8e 18 [2] a0 18 [2] 9f 04 }

  condition:
    any of them
}