rule TTP_XOR_WriteProcessMemory_fdff {
  strings:
    $key_fdff = { aa 8d [2] 98 af [2] 9e 9a [2] b0 9a [2] 8f 86 }

  condition:
    any of them
}