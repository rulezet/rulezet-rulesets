rule TTP_XOR_WriteProcessMemory_9075 {
  strings:
    $key_9075 = { c7 07 [2] f5 25 [2] f3 10 [2] dd 10 [2] e2 0c }

  condition:
    any of them
}