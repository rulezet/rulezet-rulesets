rule TTP_XOR_WriteProcessMemory_68fc {
  strings:
    $key_68fc = { 3f 8e [2] 0d ac [2] 0b 99 [2] 25 99 [2] 1a 85 }

  condition:
    any of them
}