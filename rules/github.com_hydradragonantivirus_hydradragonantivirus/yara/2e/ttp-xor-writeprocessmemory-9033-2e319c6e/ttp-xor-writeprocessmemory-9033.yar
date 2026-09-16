rule TTP_XOR_WriteProcessMemory_9033 {
  strings:
    $key_9033 = { c7 41 [2] f5 63 [2] f3 56 [2] dd 56 [2] e2 4a }

  condition:
    any of them
}