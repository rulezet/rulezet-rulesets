rule TTP_XOR_WriteProcessMemory_4be8 {
  strings:
    $key_4be8 = { 1c 9a [2] 2e b8 [2] 28 8d [2] 06 8d [2] 39 91 }

  condition:
    any of them
}