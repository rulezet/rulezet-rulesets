rule TTP_XOR_WriteProcessMemory_90f8 {
  strings:
    $key_90f8 = { c7 8a [2] f5 a8 [2] f3 9d [2] dd 9d [2] e2 81 }

  condition:
    any of them
}