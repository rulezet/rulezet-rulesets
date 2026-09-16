rule TTP_XOR_WriteProcessMemory_ed0a {
  strings:
    $key_ed0a = { ba 78 [2] 88 5a [2] 8e 6f [2] a0 6f [2] 9f 73 }

  condition:
    any of them
}