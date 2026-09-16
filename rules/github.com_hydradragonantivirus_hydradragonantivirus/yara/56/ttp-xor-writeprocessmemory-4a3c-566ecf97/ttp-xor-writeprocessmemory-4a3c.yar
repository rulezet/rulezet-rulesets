rule TTP_XOR_WriteProcessMemory_4a3c {
  strings:
    $key_4a3c = { 1d 4e [2] 2f 6c [2] 29 59 [2] 07 59 [2] 38 45 }

  condition:
    any of them
}