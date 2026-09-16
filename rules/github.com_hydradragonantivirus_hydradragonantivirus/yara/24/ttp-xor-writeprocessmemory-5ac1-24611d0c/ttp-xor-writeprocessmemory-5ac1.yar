rule TTP_XOR_WriteProcessMemory_5ac1 {
  strings:
    $key_5ac1 = { 0d b3 [2] 3f 91 [2] 39 a4 [2] 17 a4 [2] 28 b8 }

  condition:
    any of them
}