rule TTP_XOR_WriteProcessMemory_7910 {
  strings:
    $key_7910 = { 2e 62 [2] 1c 40 [2] 1a 75 [2] 34 75 [2] 0b 69 }

  condition:
    any of them
}