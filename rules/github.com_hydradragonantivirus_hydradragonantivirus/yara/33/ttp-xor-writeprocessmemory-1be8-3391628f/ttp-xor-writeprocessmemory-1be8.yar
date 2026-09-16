rule TTP_XOR_WriteProcessMemory_1be8 {
  strings:
    $key_1be8 = { 4c 9a [2] 7e b8 [2] 78 8d [2] 56 8d [2] 69 91 }

  condition:
    any of them
}