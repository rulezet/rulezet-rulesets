rule TTP_XOR_WriteProcessMemory_3be8 {
  strings:
    $key_3be8 = { 6c 9a [2] 5e b8 [2] 58 8d [2] 76 8d [2] 49 91 }

  condition:
    any of them
}