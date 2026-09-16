rule TTP_XOR_WriteProcessMemory_3328 {
  strings:
    $key_3328 = { 64 5a [2] 56 78 [2] 50 4d [2] 7e 4d [2] 41 51 }

  condition:
    any of them
}