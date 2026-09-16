rule TTP_XOR_WriteProcessMemory_7d69 {
  strings:
    $key_7d69 = { 2a 1b [2] 18 39 [2] 1e 0c [2] 30 0c [2] 0f 10 }

  condition:
    any of them
}