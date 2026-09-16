rule TTP_XOR_WriteProcessMemory_1328 {
  strings:
    $key_1328 = { 44 5a [2] 76 78 [2] 70 4d [2] 5e 4d [2] 61 51 }

  condition:
    any of them
}