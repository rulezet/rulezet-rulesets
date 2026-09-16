rule TTP_XOR_WriteProcessMemory_3a2c {
  strings:
    $key_3a2c = { 6d 5e [2] 5f 7c [2] 59 49 [2] 77 49 [2] 48 55 }

  condition:
    any of them
}