rule TTP_XOR_WriteProcessMemory_7d4c {
  strings:
    $key_7d4c = { 2a 3e [2] 18 1c [2] 1e 29 [2] 30 29 [2] 0f 35 }

  condition:
    any of them
}