rule TTP_XOR_WriteProcessMemory_7e20 {
  strings:
    $key_7e20 = { 29 52 [2] 1b 70 [2] 1d 45 [2] 33 45 [2] 0c 59 }

  condition:
    any of them
}