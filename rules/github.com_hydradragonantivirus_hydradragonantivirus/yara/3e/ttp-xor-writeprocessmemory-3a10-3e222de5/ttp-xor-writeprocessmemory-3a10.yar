rule TTP_XOR_WriteProcessMemory_3a10 {
  strings:
    $key_3a10 = { 6d 62 [2] 5f 40 [2] 59 75 [2] 77 75 [2] 48 69 }

  condition:
    any of them
}