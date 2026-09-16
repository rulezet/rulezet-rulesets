rule TTP_XOR_WriteProcessMemory_154c {
  strings:
    $key_154c = { 42 3e [2] 70 1c [2] 76 29 [2] 58 29 [2] 67 35 }

  condition:
    any of them
}