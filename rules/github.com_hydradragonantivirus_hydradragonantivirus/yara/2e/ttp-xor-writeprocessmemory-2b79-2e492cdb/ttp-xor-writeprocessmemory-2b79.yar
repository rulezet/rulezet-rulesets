rule TTP_XOR_WriteProcessMemory_2b79 {
  strings:
    $key_2b79 = { 7c 0b [2] 4e 29 [2] 48 1c [2] 66 1c [2] 59 00 }

  condition:
    any of them
}