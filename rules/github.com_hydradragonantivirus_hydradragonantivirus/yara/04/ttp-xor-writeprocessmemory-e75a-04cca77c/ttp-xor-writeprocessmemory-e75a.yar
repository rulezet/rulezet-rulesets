rule TTP_XOR_WriteProcessMemory_e75a {
  strings:
    $key_e75a = { b0 28 [2] 82 0a [2] 84 3f [2] aa 3f [2] 95 23 }

  condition:
    any of them
}