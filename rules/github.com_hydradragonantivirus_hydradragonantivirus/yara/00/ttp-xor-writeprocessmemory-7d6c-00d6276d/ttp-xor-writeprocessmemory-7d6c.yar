rule TTP_XOR_WriteProcessMemory_7d6c {
  strings:
    $key_7d6c = { 2a 1e [2] 18 3c [2] 1e 09 [2] 30 09 [2] 0f 15 }

  condition:
    any of them
}