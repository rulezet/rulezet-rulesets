rule TTP_XOR_WriteProcessMemory_ed5a {
  strings:
    $key_ed5a = { ba 28 [2] 88 0a [2] 8e 3f [2] a0 3f [2] 9f 23 }

  condition:
    any of them
}