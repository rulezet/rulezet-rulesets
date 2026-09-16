rule TTP_XOR_WriteProcessMemory_5901 {
  strings:
    $key_5901 = { 0e 73 [2] 3c 51 [2] 3a 64 [2] 14 64 [2] 2b 78 }

  condition:
    any of them
}