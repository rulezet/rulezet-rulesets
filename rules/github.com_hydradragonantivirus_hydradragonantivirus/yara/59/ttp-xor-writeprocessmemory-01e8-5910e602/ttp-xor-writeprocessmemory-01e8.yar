rule TTP_XOR_WriteProcessMemory_01e8 {
  strings:
    $key_01e8 = { 56 9a [2] 64 b8 [2] 62 8d [2] 4c 8d [2] 73 91 }

  condition:
    any of them
}