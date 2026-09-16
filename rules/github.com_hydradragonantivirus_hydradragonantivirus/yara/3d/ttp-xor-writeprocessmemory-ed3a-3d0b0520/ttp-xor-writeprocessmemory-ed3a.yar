rule TTP_XOR_WriteProcessMemory_ed3a {
  strings:
    $key_ed3a = { ba 48 [2] 88 6a [2] 8e 5f [2] a0 5f [2] 9f 43 }

  condition:
    any of them
}