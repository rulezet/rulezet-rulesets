rule TTP_XOR_WriteProcessMemory_7e54 {
  strings:
    $key_7e54 = { 29 26 [2] 1b 04 [2] 1d 31 [2] 33 31 [2] 0c 2d }

  condition:
    any of them
}