rule TTP_XOR_WriteProcessMemory_1828 {
  strings:
    $key_1828 = { 4f 5a [2] 7d 78 [2] 7b 4d [2] 55 4d [2] 6a 51 }

  condition:
    any of them
}