rule TTP_XOR_WriteProcessMemory_3a1d {
  strings:
    $key_3a1d = { 6d 6f [2] 5f 4d [2] 59 78 [2] 77 78 [2] 48 64 }

  condition:
    any of them
}