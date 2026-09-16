rule TTP_XOR_WriteProcessMemory_7979 {
  strings:
    $key_7979 = { 2e 0b [2] 1c 29 [2] 1a 1c [2] 34 1c [2] 0b 00 }

  condition:
    any of them
}