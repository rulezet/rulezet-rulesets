rule TTP_XOR_WriteProcessMemory_5b20 {
  strings:
    $key_5b20 = { 0c 52 [2] 3e 70 [2] 38 45 [2] 16 45 [2] 29 59 }

  condition:
    any of them
}