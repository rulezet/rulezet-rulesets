rule TTP_XOR_WriteProcessMemory_2e3c {
  strings:
    $key_2e3c = { 79 4e [2] 4b 6c [2] 4d 59 [2] 63 59 [2] 5c 45 }

  condition:
    any of them
}