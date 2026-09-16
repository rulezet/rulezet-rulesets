rule TTP_XOR_WriteProcessMemory_7d19 {
  strings:
    $key_7d19 = { 2a 6b [2] 18 49 [2] 1e 7c [2] 30 7c [2] 0f 60 }

  condition:
    any of them
}