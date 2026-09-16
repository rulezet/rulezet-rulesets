rule TTP_XOR_WriteProcessMemory_ed2f {
  strings:
    $key_ed2f = { ba 5d [2] 88 7f [2] 8e 4a [2] a0 4a [2] 9f 56 }

  condition:
    any of them
}