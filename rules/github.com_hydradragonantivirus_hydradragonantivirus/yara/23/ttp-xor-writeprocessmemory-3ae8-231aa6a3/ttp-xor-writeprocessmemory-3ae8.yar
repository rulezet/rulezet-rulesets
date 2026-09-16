rule TTP_XOR_WriteProcessMemory_3ae8 {
  strings:
    $key_3ae8 = { 6d 9a [2] 5f b8 [2] 59 8d [2] 77 8d [2] 48 91 }

  condition:
    any of them
}