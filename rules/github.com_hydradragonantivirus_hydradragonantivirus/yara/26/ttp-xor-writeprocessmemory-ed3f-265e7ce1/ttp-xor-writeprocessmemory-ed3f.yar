rule TTP_XOR_WriteProcessMemory_ed3f {
  strings:
    $key_ed3f = { ba 4d [2] 88 6f [2] 8e 5a [2] a0 5a [2] 9f 46 }

  condition:
    any of them
}