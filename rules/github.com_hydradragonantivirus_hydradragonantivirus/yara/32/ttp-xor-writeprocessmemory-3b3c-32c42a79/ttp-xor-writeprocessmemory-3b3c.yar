rule TTP_XOR_WriteProcessMemory_3b3c {
  strings:
    $key_3b3c = { 6c 4e [2] 5e 6c [2] 58 59 [2] 76 59 [2] 49 45 }

  condition:
    any of them
}