rule TTP_XOR_WriteProcessMemory_7d10 {
  strings:
    $key_7d10 = { 2a 62 [2] 18 40 [2] 1e 75 [2] 30 75 [2] 0f 69 }

  condition:
    any of them
}