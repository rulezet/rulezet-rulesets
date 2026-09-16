rule TTP_XOR_WriteProcessMemory_7901 {
  strings:
    $key_7901 = { 2e 73 [2] 1c 51 [2] 1a 64 [2] 34 64 [2] 0b 78 }

  condition:
    any of them
}