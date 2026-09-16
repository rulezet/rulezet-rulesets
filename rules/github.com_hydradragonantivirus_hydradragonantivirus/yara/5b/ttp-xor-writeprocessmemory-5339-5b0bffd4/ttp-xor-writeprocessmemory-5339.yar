rule TTP_XOR_WriteProcessMemory_5339 {
  strings:
    $key_5339 = { 04 4b [2] 36 69 [2] 30 5c [2] 1e 5c [2] 21 40 }

  condition:
    any of them
}