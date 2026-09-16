rule TTP_XOR_WriteProcessMemory_685b {
  strings:
    $key_685b = { 3f 29 [2] 0d 0b [2] 0b 3e [2] 25 3e [2] 1a 22 }

  condition:
    any of them
}