rule TTP_XOR_WriteProcessMemory_2d59 {
  strings:
    $key_2d59 = { 7a 2b [2] 48 09 [2] 4e 3c [2] 60 3c [2] 5f 20 }

  condition:
    any of them
}