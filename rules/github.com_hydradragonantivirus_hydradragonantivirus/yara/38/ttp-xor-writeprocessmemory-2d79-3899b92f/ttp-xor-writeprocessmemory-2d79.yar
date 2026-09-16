rule TTP_XOR_WriteProcessMemory_2d79 {
  strings:
    $key_2d79 = { 7a 0b [2] 48 29 [2] 4e 1c [2] 60 1c [2] 5f 00 }

  condition:
    any of them
}