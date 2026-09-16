rule TTP_XOR_WriteProcessMemory_820a {
  strings:
    $key_820a = { d5 78 [2] e7 5a [2] e1 6f [2] cf 6f [2] f0 73 }

  condition:
    any of them
}