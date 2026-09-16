rule TTP_XOR_WriteProcessMemory_6428 {
  strings:
    $key_6428 = { 33 5a [2] 01 78 [2] 07 4d [2] 29 4d [2] 16 51 }

  condition:
    any of them
}