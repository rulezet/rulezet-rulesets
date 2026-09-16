rule TTP_XOR_WriteProcessMemory_0b28 {
  strings:
    $key_0b28 = { 5c 5a [2] 6e 78 [2] 68 4d [2] 46 4d [2] 79 51 }

  condition:
    any of them
}