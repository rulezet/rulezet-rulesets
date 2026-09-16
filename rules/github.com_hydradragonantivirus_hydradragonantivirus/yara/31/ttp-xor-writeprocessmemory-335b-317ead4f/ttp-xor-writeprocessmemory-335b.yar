rule TTP_XOR_WriteProcessMemory_335b {
  strings:
    $key_335b = { 64 29 [2] 56 0b [2] 50 3e [2] 7e 3e [2] 41 22 }

  condition:
    any of them
}