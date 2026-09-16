rule TTP_XOR_WriteProcessMemory_2e79 {
  strings:
    $key_2e79 = { 79 0b [2] 4b 29 [2] 4d 1c [2] 63 1c [2] 5c 00 }

  condition:
    any of them
}