rule TTP_XOR_WriteProcessMemory_e979 {
  strings:
    $key_e979 = { be 0b [2] 8c 29 [2] 8a 1c [2] a4 1c [2] 9b 00 }

  condition:
    any of them
}