rule TTP_XOR_WriteProcessMemory_6278 {
  strings:
    $key_6278 = { 35 0a [2] 07 28 [2] 01 1d [2] 2f 1d [2] 10 01 }

  condition:
    any of them
}