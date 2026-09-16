rule TTP_XOR_WriteProcessMemory_907a {
  strings:
    $key_907a = { c7 08 [2] f5 2a [2] f3 1f [2] dd 1f [2] e2 03 }

  condition:
    any of them
}