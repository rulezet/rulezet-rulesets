rule TTP_XOR_WriteProcessMemory_2d4c {
  strings:
    $key_2d4c = { 7a 3e [2] 48 1c [2] 4e 29 [2] 60 29 [2] 5f 35 }

  condition:
    any of them
}