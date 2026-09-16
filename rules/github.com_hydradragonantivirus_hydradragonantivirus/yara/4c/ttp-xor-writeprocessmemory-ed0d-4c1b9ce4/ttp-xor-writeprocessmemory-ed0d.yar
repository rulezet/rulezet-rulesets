rule TTP_XOR_WriteProcessMemory_ed0d {
  strings:
    $key_ed0d = { ba 7f [2] 88 5d [2] 8e 68 [2] a0 68 [2] 9f 74 }

  condition:
    any of them
}