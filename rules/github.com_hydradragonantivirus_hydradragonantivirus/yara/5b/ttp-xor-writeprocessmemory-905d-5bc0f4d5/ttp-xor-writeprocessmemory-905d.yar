rule TTP_XOR_WriteProcessMemory_905d {
  strings:
    $key_905d = { c7 2f [2] f5 0d [2] f3 38 [2] dd 38 [2] e2 24 }

  condition:
    any of them
}