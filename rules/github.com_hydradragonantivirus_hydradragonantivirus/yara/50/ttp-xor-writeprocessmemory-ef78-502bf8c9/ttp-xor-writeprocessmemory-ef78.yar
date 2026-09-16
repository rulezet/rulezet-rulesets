rule TTP_XOR_WriteProcessMemory_ef78 {
  strings:
    $key_ef78 = { b8 0a [2] 8a 28 [2] 8c 1d [2] a2 1d [2] 9d 01 }

  condition:
    any of them
}