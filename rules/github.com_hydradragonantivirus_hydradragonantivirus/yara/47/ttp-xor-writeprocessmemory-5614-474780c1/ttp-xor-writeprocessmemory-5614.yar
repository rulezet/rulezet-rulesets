rule TTP_XOR_WriteProcessMemory_5614 {
  strings:
    $key_5614 = { 01 66 [2] 33 44 [2] 35 71 [2] 1b 71 [2] 24 6d }

  condition:
    any of them
}