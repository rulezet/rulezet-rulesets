rule TTP_XOR_WriteProcessMemory_5d79 {
  strings:
    $key_5d79 = { 0a 0b [2] 38 29 [2] 3e 1c [2] 10 1c [2] 2f 00 }

  condition:
    any of them
}