rule TTP_XOR_WriteProcessMemory_6468 {
  strings:
    $key_6468 = { 33 1a [2] 01 38 [2] 07 0d [2] 29 0d [2] 16 11 }

  condition:
    any of them
}