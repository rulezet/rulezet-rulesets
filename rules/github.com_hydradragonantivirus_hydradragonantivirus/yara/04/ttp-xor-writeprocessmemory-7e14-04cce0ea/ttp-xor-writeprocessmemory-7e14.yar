rule TTP_XOR_WriteProcessMemory_7e14 {
  strings:
    $key_7e14 = { 29 66 [2] 1b 44 [2] 1d 71 [2] 33 71 [2] 0c 6d }

  condition:
    any of them
}