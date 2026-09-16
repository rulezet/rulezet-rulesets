rule TTP_XOR_WriteProcessMemory_837a {
  strings:
    $key_837a = { d4 08 [2] e6 2a [2] e0 1f [2] ce 1f [2] f1 03 }

  condition:
    any of them
}