rule TTP_XOR_WriteProcessMemory_ed68 {
  strings:
    $key_ed68 = { ba 1a [2] 88 38 [2] 8e 0d [2] a0 0d [2] 9f 11 }

  condition:
    any of them
}