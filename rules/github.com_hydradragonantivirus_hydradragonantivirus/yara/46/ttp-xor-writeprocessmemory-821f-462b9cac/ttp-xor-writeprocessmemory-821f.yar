rule TTP_XOR_WriteProcessMemory_821f {
  strings:
    $key_821f = { d5 6d [2] e7 4f [2] e1 7a [2] cf 7a [2] f0 66 }

  condition:
    any of them
}