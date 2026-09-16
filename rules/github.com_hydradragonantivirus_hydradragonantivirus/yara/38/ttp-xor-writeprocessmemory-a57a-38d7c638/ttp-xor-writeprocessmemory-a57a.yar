rule TTP_XOR_WriteProcessMemory_a57a {
  strings:
    $key_a57a = { f2 08 [2] c0 2a [2] c6 1f [2] e8 1f [2] d7 03 }

  condition:
    any of them
}