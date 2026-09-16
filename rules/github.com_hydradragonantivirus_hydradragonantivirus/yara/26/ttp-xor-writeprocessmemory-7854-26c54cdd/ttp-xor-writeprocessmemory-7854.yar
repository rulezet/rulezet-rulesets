rule TTP_XOR_WriteProcessMemory_7854 {
  strings:
    $key_7854 = { 2f 26 [2] 1d 04 [2] 1b 31 [2] 35 31 [2] 0a 2d }

  condition:
    any of them
}