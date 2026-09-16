rule TTP_XOR_WriteProcessMemory_5934 {
  strings:
    $key_5934 = { 0e 46 [2] 3c 64 [2] 3a 51 [2] 14 51 [2] 2b 4d }

  condition:
    any of them
}