rule TTP_XOR_WriteProcessMemory_7e24 {
  strings:
    $key_7e24 = { 29 56 [2] 1b 74 [2] 1d 41 [2] 33 41 [2] 0c 5d }

  condition:
    any of them
}