rule TTP_XOR_WriteProcessMemory_7e04 {
  strings:
    $key_7e04 = { 29 76 [2] 1b 54 [2] 1d 61 [2] 33 61 [2] 0c 7d }

  condition:
    any of them
}