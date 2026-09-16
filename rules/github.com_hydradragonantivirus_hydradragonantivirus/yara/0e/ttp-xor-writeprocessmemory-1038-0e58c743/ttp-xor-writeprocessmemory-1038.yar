rule TTP_XOR_WriteProcessMemory_1038 {
  strings:
    $key_1038 = { 47 4a [2] 75 68 [2] 73 5d [2] 5d 5d [2] 62 41 }

  condition:
    any of them
}