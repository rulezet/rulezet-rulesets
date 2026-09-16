rule TTP_XOR_WriteProcessMemory_ed4a {
  strings:
    $key_ed4a = { ba 38 [2] 88 1a [2] 8e 2f [2] a0 2f [2] 9f 33 }

  condition:
    any of them
}