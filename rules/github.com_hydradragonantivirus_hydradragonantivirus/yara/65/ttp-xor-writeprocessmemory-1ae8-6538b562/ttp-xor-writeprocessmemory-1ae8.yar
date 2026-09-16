rule TTP_XOR_WriteProcessMemory_1ae8 {
  strings:
    $key_1ae8 = { 4d 9a [2] 7f b8 [2] 79 8d [2] 57 8d [2] 68 91 }

  condition:
    any of them
}