rule TTP_XOR_WriteProcessMemory_783c {
  strings:
    $key_783c = { 2f 4e [2] 1d 6c [2] 1b 59 [2] 35 59 [2] 0a 45 }

  condition:
    any of them
}