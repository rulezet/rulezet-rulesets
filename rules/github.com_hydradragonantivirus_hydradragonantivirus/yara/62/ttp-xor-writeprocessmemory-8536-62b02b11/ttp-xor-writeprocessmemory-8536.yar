rule TTP_XOR_WriteProcessMemory_8536 {
  strings:
    $key_8536 = { d2 44 [2] e0 66 [2] e6 53 [2] c8 53 [2] f7 4f }

  condition:
    any of them
}