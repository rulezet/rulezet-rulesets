rule TTP_XOR_WriteProcessMemory_6965 {
  strings:
    $key_6965 = { 3e 17 [2] 0c 35 [2] 0a 00 [2] 24 00 [2] 1b 1c }

  condition:
    any of them
}