rule TTP_XOR_WriteProcessMemory_7824 {
  strings:
    $key_7824 = { 2f 56 [2] 1d 74 [2] 1b 41 [2] 35 41 [2] 0a 5d }

  condition:
    any of them
}