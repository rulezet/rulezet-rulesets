rule TTP_XOR_WriteProcessMemory_51e8 {
  strings:
    $key_51e8 = { 06 9a [2] 34 b8 [2] 32 8d [2] 1c 8d [2] 23 91 }

  condition:
    any of them
}