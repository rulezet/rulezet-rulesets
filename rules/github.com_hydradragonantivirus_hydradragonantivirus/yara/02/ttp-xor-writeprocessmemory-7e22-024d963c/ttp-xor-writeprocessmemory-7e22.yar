rule TTP_XOR_WriteProcessMemory_7e22 {
  strings:
    $key_7e22 = { 29 50 [2] 1b 72 [2] 1d 47 [2] 33 47 [2] 0c 5b }

  condition:
    any of them
}