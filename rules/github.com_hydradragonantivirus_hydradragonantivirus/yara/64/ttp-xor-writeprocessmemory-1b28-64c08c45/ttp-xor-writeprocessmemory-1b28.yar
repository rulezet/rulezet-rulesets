rule TTP_XOR_WriteProcessMemory_1b28 {
  strings:
    $key_1b28 = { 4c 5a [2] 7e 78 [2] 78 4d [2] 56 4d [2] 69 51 }

  condition:
    any of them
}