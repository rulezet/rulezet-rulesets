rule TTP_XOR_WriteProcessMemory_7d59 {
  strings:
    $key_7d59 = { 2a 2b [2] 18 09 [2] 1e 3c [2] 30 3c [2] 0f 20 }

  condition:
    any of them
}