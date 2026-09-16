rule TTP_XOR_WriteProcessMemory_ef48 {
  strings:
    $key_ef48 = { b8 3a [2] 8a 18 [2] 8c 2d [2] a2 2d [2] 9d 31 }

  condition:
    any of them
}