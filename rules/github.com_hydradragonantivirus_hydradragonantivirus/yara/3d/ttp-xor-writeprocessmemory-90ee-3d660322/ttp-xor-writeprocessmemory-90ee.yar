rule TTP_XOR_WriteProcessMemory_90ee {
  strings:
    $key_90ee = { c7 9c [2] f5 be [2] f3 8b [2] dd 8b [2] e2 97 }

  condition:
    any of them
}