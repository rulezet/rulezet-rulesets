rule TTP_XOR_WriteProcessMemory_394c {
  strings:
    $key_394c = { 6e 3e [2] 5c 1c [2] 5a 29 [2] 74 29 [2] 4b 35 }

  condition:
    any of them
}