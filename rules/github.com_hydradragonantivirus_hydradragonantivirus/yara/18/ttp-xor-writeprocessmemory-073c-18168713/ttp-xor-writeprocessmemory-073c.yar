rule TTP_XOR_WriteProcessMemory_073c {
  strings:
    $key_073c = { 50 4e [2] 62 6c [2] 64 59 [2] 4a 59 [2] 75 45 }

  condition:
    any of them
}