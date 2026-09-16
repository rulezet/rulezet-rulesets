rule TTP_XOR_WriteProcessMemory_7e52 {
  strings:
    $key_7e52 = { 29 20 [2] 1b 02 [2] 1d 37 [2] 33 37 [2] 0c 2b }

  condition:
    any of them
}