rule TTP_XOR_WriteProcessMemory_6950 {
  strings:
    $key_6950 = { 3e 22 [2] 0c 00 [2] 0a 35 [2] 24 35 [2] 1b 29 }

  condition:
    any of them
}