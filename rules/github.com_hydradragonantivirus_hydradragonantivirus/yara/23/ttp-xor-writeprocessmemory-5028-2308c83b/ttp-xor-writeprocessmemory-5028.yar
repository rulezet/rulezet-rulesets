rule TTP_XOR_WriteProcessMemory_5028 {
  strings:
    $key_5028 = { 07 5a [2] 35 78 [2] 33 4d [2] 1d 4d [2] 22 51 }

  condition:
    any of them
}