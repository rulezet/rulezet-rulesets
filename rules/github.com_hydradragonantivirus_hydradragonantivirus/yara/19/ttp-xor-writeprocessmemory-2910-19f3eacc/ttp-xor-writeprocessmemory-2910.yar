rule TTP_XOR_WriteProcessMemory_2910 {
  strings:
    $key_2910 = { 7e 62 [2] 4c 40 [2] 4a 75 [2] 64 75 [2] 5b 69 }

  condition:
    any of them
}