rule TTP_XOR_WriteProcessMemory_7d39 {
  strings:
    $key_7d39 = { 2a 4b [2] 18 69 [2] 1e 5c [2] 30 5c [2] 0f 40 }

  condition:
    any of them
}