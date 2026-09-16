rule TTP_XOR_WriteProcessMemory_3c48 {
  strings:
    $key_3c48 = { 6b 3a [2] 59 18 [2] 5f 2d [2] 71 2d [2] 4e 31 }

  condition:
    any of them
}