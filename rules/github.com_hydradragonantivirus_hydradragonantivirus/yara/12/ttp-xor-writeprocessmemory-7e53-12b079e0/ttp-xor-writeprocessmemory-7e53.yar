rule TTP_XOR_WriteProcessMemory_7e53 {
  strings:
    $key_7e53 = { 29 21 [2] 1b 03 [2] 1d 36 [2] 33 36 [2] 0c 2a }

  condition:
    any of them
}