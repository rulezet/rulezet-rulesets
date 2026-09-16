rule TTP_XOR_WriteProcessMemory_15e8 {
  strings:
    $key_15e8 = { 42 9a [2] 70 b8 [2] 76 8d [2] 58 8d [2] 67 91 }

  condition:
    any of them
}