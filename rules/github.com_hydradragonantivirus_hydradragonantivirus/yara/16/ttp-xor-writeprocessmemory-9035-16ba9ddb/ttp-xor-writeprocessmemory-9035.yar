rule TTP_XOR_WriteProcessMemory_9035 {
  strings:
    $key_9035 = { c7 47 [2] f5 65 [2] f3 50 [2] dd 50 [2] e2 4c }

  condition:
    any of them
}