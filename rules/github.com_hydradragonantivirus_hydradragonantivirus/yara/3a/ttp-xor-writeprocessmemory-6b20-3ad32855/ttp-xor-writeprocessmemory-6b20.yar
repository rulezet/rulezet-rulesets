rule TTP_XOR_WriteProcessMemory_6b20 {
  strings:
    $key_6b20 = { 3c 52 [2] 0e 70 [2] 08 45 [2] 26 45 [2] 19 59 }

  condition:
    any of them
}