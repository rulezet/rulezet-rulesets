rule TTP_XOR_WriteProcessMemory_7e40 {
  strings:
    $key_7e40 = { 29 32 [2] 1b 10 [2] 1d 25 [2] 33 25 [2] 0c 39 }

  condition:
    any of them
}