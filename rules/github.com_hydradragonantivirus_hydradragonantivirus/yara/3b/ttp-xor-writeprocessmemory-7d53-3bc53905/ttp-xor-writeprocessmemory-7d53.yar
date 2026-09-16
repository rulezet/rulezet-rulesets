rule TTP_XOR_WriteProcessMemory_7d53 {
  strings:
    $key_7d53 = { 2a 21 [2] 18 03 [2] 1e 36 [2] 30 36 [2] 0f 2a }

  condition:
    any of them
}