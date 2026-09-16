rule TTP_XOR_WriteProcessMemory_7d0c {
  strings:
    $key_7d0c = { 2a 7e [2] 18 5c [2] 1e 69 [2] 30 69 [2] 0f 75 }

  condition:
    any of them
}