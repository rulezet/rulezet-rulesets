rule TTP_XOR_WriteProcessMemory_4e79 {
  strings:
    $key_4e79 = { 19 0b [2] 2b 29 [2] 2d 1c [2] 03 1c [2] 3c 00 }

  condition:
    any of them
}