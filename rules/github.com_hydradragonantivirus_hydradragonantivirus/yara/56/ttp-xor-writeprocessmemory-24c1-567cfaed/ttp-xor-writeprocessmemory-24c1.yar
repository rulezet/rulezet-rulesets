rule TTP_XOR_WriteProcessMemory_24c1 {
  strings:
    $key_24c1 = { 73 b3 [2] 41 91 [2] 47 a4 [2] 69 a4 [2] 56 b8 }

  condition:
    any of them
}