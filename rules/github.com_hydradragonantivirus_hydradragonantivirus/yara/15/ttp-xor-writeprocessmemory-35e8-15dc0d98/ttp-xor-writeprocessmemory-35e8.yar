rule TTP_XOR_WriteProcessMemory_35e8 {
  strings:
    $key_35e8 = { 62 9a [2] 50 b8 [2] 56 8d [2] 78 8d [2] 47 91 }

  condition:
    any of them
}