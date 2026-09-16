rule TTP_XOR_WriteProcessMemory_7d70 {
  strings:
    $key_7d70 = { 2a 02 [2] 18 20 [2] 1e 15 [2] 30 15 [2] 0f 09 }

  condition:
    any of them
}