rule TTP_XOR_WriteProcessMemory_5a3c {
  strings:
    $key_5a3c = { 0d 4e [2] 3f 6c [2] 39 59 [2] 17 59 [2] 28 45 }

  condition:
    any of them
}