rule TTP_XOR_WriteProcessMemory_9031 {
  strings:
    $key_9031 = { c7 43 [2] f5 61 [2] f3 54 [2] dd 54 [2] e2 48 }

  condition:
    any of them
}