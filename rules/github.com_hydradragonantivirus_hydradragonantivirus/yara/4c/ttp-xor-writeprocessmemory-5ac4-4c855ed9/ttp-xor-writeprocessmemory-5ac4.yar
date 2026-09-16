rule TTP_XOR_WriteProcessMemory_5ac4 {
  strings:
    $key_5ac4 = { 0d b6 [2] 3f 94 [2] 39 a1 [2] 17 a1 [2] 28 bd }

  condition:
    any of them
}