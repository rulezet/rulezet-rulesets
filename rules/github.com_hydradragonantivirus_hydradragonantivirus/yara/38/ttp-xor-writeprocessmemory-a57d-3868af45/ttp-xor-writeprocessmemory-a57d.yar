rule TTP_XOR_WriteProcessMemory_a57d {
  strings:
    $key_a57d = { f2 0f [2] c0 2d [2] c6 18 [2] e8 18 [2] d7 04 }

  condition:
    any of them
}