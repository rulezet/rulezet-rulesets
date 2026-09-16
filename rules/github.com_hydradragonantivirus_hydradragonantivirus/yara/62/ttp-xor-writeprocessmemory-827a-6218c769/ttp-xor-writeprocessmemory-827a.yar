rule TTP_XOR_WriteProcessMemory_827a {
  strings:
    $key_827a = { d5 08 [2] e7 2a [2] e1 1f [2] cf 1f [2] f0 03 }

  condition:
    any of them
}