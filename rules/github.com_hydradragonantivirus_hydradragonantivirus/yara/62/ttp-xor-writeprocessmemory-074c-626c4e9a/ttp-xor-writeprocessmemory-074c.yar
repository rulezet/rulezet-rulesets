rule TTP_XOR_WriteProcessMemory_074c {
  strings:
    $key_074c = { 50 3e [2] 62 1c [2] 64 29 [2] 4a 29 [2] 75 35 }

  condition:
    any of them
}