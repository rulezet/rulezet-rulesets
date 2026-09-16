rule TTP_XOR_WriteProcessMemory_e77f {
  strings:
    $key_e77f = { b0 0d [2] 82 2f [2] 84 1a [2] aa 1a [2] 95 06 }

  condition:
    any of them
}