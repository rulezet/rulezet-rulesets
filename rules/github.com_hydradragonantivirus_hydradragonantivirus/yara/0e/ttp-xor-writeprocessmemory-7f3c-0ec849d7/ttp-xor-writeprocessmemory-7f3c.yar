rule TTP_XOR_WriteProcessMemory_7f3c {
  strings:
    $key_7f3c = { 28 4e [2] 1a 6c [2] 1c 59 [2] 32 59 [2] 0d 45 }

  condition:
    any of them
}