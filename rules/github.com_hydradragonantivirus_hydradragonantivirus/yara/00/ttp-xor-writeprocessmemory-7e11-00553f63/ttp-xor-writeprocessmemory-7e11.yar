rule TTP_XOR_WriteProcessMemory_7e11 {
  strings:
    $key_7e11 = { 29 63 [2] 1b 41 [2] 1d 74 [2] 33 74 [2] 0c 68 }

  condition:
    any of them
}