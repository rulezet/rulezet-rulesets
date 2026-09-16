rule TTP_XOR_WriteProcessMemory_1078 {
  strings:
    $key_1078 = { 47 0a [2] 75 28 [2] 73 1d [2] 5d 1d [2] 62 01 }

  condition:
    any of them
}