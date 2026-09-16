rule TTP_XOR_WriteProcessMemory_7e3c {
  strings:
    $key_7e3c = { 29 4e [2] 1b 6c [2] 1d 59 [2] 33 59 [2] 0c 45 }

  condition:
    any of them
}