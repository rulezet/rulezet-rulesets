rule TTP_XOR_WriteProcessMemory_ed6f {
  strings:
    $key_ed6f = { ba 1d [2] 88 3f [2] 8e 0a [2] a0 0a [2] 9f 16 }

  condition:
    any of them
}