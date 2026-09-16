rule TTP_XOR_WriteProcessMemory_90ff {
  strings:
    $key_90ff = { c7 8d [2] f5 af [2] f3 9a [2] dd 9a [2] e2 86 }

  condition:
    any of them
}