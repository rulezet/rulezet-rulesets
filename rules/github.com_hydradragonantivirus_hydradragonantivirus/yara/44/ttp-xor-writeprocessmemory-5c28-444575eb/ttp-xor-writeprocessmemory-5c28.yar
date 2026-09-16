rule TTP_XOR_WriteProcessMemory_5c28 {
  strings:
    $key_5c28 = { 0b 5a [2] 39 78 [2] 3f 4d [2] 11 4d [2] 2e 51 }

  condition:
    any of them
}