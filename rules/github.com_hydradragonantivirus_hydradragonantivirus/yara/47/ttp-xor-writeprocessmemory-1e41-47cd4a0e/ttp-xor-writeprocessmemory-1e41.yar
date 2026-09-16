rule TTP_XOR_WriteProcessMemory_1e41 {
  strings:
    $key_1e41 = { 49 33 [2] 7b 11 [2] 7d 24 [2] 53 24 [2] 6c 38 }

  condition:
    any of them
}