rule TTP_XOR_WriteProcessMemory_ed5f {
  strings:
    $key_ed5f = { ba 2d [2] 88 0f [2] 8e 3a [2] a0 3a [2] 9f 26 }

  condition:
    any of them
}