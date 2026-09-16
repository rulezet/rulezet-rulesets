rule TTP_XOR_WriteProcessMemory_7e41 {
  strings:
    $key_7e41 = { 29 33 [2] 1b 11 [2] 1d 24 [2] 33 24 [2] 0c 38 }

  condition:
    any of them
}