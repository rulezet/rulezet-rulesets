rule TTP_XOR_WriteProcessMemory_5078 {
  strings:
    $key_5078 = { 07 0a [2] 35 28 [2] 33 1d [2] 1d 1d [2] 22 01 }

  condition:
    any of them
}