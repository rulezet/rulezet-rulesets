rule TTP_XOR_WriteProcessMemory_7e71 {
  strings:
    $key_7e71 = { 29 03 [2] 1b 21 [2] 1d 14 [2] 33 14 [2] 0c 08 }

  condition:
    any of them
}