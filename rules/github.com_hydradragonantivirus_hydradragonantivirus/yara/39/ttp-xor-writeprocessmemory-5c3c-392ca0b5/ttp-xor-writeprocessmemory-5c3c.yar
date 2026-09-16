rule TTP_XOR_WriteProcessMemory_5c3c {
  strings:
    $key_5c3c = { 0b 4e [2] 39 6c [2] 3f 59 [2] 11 59 [2] 2e 45 }

  condition:
    any of them
}