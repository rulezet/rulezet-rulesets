rule TTP_XOR_WriteProcessMemory_2be8 {
  strings:
    $key_2be8 = { 7c 9a [2] 4e b8 [2] 48 8d [2] 66 8d [2] 59 91 }

  condition:
    any of them
}