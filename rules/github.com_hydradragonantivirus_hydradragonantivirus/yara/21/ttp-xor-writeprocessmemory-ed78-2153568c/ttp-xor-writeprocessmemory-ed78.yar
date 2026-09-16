rule TTP_XOR_WriteProcessMemory_ed78 {
  strings:
    $key_ed78 = { ba 0a [2] 88 28 [2] 8e 1d [2] a0 1d [2] 9f 01 }

  condition:
    any of them
}