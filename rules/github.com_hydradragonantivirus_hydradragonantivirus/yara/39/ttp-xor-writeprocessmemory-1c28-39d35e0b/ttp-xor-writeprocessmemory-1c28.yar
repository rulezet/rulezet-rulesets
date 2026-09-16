rule TTP_XOR_WriteProcessMemory_1c28 {
  strings:
    $key_1c28 = { 4b 5a [2] 79 78 [2] 7f 4d [2] 51 4d [2] 6e 51 }

  condition:
    any of them
}