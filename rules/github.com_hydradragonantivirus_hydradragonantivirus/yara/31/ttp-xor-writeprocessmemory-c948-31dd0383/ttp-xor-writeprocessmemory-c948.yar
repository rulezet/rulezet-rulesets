rule TTP_XOR_WriteProcessMemory_c948 {
  strings:
    $key_c948 = { 9e 3a [2] ac 18 [2] aa 2d [2] 84 2d [2] bb 31 }

  condition:
    any of them
}