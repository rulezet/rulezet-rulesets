rule TTP_XOR_WriteProcessMemory_0e41 {
  strings:
    $key_0e41 = { 59 33 [2] 6b 11 [2] 6d 24 [2] 43 24 [2] 7c 38 }

  condition:
    any of them
}