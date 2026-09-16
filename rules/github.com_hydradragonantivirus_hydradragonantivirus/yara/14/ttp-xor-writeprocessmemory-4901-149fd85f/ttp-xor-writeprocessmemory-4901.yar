rule TTP_XOR_WriteProcessMemory_4901 {
  strings:
    $key_4901 = { 1e 73 [2] 2c 51 [2] 2a 64 [2] 04 64 [2] 3b 78 }

  condition:
    any of them
}