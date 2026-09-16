rule TTP_XOR_WriteProcessMemory_2a3c {
  strings:
    $key_2a3c = { 7d 4e [2] 4f 6c [2] 49 59 [2] 67 59 [2] 58 45 }

  condition:
    any of them
}