rule TTP_XOR_WriteProcessMemory_90ca {
  strings:
    $key_90ca = { c7 b8 [2] f5 9a [2] f3 af [2] dd af [2] e2 b3 }

  condition:
    any of them
}