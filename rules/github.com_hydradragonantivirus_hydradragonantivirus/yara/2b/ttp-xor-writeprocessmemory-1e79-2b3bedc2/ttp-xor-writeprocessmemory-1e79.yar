rule TTP_XOR_WriteProcessMemory_1e79 {
  strings:
    $key_1e79 = { 49 0b [2] 7b 29 [2] 7d 1c [2] 53 1c [2] 6c 00 }

  condition:
    any of them
}