rule TTP_XOR_WriteProcessMemory_edeb {
  strings:
    $key_edeb = { ba 99 [2] 88 bb [2] 8e 8e [2] a0 8e [2] 9f 92 }

  condition:
    any of them
}