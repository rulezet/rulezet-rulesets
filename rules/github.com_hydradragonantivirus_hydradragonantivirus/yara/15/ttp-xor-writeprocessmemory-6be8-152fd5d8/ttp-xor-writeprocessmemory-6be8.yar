rule TTP_XOR_WriteProcessMemory_6be8 {
  strings:
    $key_6be8 = { 3c 9a [2] 0e b8 [2] 08 8d [2] 26 8d [2] 19 91 }

  condition:
    any of them
}