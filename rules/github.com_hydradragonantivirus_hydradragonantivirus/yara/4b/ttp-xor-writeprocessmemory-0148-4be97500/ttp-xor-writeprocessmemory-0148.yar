rule TTP_XOR_WriteProcessMemory_0148 {
  strings:
    $key_0148 = { 56 3a [2] 64 18 [2] 62 2d [2] 4c 2d [2] 73 31 }

  condition:
    any of them
}