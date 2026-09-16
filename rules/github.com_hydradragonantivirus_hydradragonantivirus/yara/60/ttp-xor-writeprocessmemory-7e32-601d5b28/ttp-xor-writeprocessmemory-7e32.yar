rule TTP_XOR_WriteProcessMemory_7e32 {
  strings:
    $key_7e32 = { 29 40 [2] 1b 62 [2] 1d 57 [2] 33 57 [2] 0c 4b }

  condition:
    any of them
}