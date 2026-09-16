rule TTP_XOR_WriteProcessMemory_902a {
  strings:
    $key_902a = { c7 58 [2] f5 7a [2] f3 4f [2] dd 4f [2] e2 53 }

  condition:
    any of them
}