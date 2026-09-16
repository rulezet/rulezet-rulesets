rule TTP_XOR_WriteProcessMemory_a57f {
  strings:
    $key_a57f = { f2 0d [2] c0 2f [2] c6 1a [2] e8 1a [2] d7 06 }

  condition:
    any of them
}