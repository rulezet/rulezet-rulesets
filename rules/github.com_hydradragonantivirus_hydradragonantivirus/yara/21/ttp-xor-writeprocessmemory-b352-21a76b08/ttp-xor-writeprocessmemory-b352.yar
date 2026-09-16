rule TTP_XOR_WriteProcessMemory_b352 {
  strings:
    $key_b352 = { e4 20 [2] d6 02 [2] d0 37 [2] fe 37 [2] c1 2b }

  condition:
    any of them
}