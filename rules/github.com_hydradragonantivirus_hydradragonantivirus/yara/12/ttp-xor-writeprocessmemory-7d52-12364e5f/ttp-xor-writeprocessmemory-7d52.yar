rule TTP_XOR_WriteProcessMemory_7d52 {
  strings:
    $key_7d52 = { 2a 20 [2] 18 02 [2] 1e 37 [2] 30 37 [2] 0f 2b }

  condition:
    any of them
}