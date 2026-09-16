rule TTP_XOR_WriteProcessMemory_4a28 {
  strings:
    $key_4a28 = { 1d 5a [2] 2f 78 [2] 29 4d [2] 07 4d [2] 38 51 }

  condition:
    any of them
}