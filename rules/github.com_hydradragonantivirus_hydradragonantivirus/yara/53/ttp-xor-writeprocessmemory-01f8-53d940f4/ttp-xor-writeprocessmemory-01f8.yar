rule TTP_XOR_WriteProcessMemory_01f8 {
  strings:
    $key_01f8 = { 56 8a [2] 64 a8 [2] 62 9d [2] 4c 9d [2] 73 81 }

  condition:
    any of them
}