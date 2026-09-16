rule TTP_XOR_WriteProcessMemory_6e79 {
  strings:
    $key_6e79 = { 39 0b [2] 0b 29 [2] 0d 1c [2] 23 1c [2] 1c 00 }

  condition:
    any of them
}