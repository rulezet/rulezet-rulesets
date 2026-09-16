rule TTP_XOR_WriteProcessMemory_7814 {
  strings:
    $key_7814 = { 2f 66 [2] 1d 44 [2] 1b 71 [2] 35 71 [2] 0a 6d }

  condition:
    any of them
}