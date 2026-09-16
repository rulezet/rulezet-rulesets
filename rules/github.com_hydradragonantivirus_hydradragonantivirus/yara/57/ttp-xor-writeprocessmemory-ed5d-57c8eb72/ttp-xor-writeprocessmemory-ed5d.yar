rule TTP_XOR_WriteProcessMemory_ed5d {
  strings:
    $key_ed5d = { ba 2f [2] 88 0d [2] 8e 38 [2] a0 38 [2] 9f 24 }

  condition:
    any of them
}