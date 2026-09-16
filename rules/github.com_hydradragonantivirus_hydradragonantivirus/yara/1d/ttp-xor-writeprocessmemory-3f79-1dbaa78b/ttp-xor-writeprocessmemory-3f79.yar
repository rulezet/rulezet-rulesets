rule TTP_XOR_WriteProcessMemory_3f79 {
  strings:
    $key_3f79 = { 68 0b [2] 5a 29 [2] 5c 1c [2] 72 1c [2] 4d 00 }

  condition:
    any of them
}