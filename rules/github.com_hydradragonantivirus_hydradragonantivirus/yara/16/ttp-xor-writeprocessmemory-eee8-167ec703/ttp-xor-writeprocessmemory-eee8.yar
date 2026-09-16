rule TTP_XOR_WriteProcessMemory_eee8 {
  strings:
    $key_eee8 = { b9 9a [2] 8b b8 [2] 8d 8d [2] a3 8d [2] 9c 91 }

  condition:
    any of them
}