rule TTP_XOR_WriteProcessMemory_6e41 {
  strings:
    $key_6e41 = { 39 33 [2] 0b 11 [2] 0d 24 [2] 23 24 [2] 1c 38 }

  condition:
    any of them
}