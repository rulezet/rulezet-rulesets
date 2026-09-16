rule TTP_XOR_WriteProcessMemory_e76f {
  strings:
    $key_e76f = { b0 1d [2] 82 3f [2] 84 0a [2] aa 0a [2] 95 16 }

  condition:
    any of them
}