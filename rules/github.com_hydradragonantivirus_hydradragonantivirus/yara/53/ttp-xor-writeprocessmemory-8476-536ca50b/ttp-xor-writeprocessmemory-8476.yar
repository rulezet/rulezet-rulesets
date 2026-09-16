rule TTP_XOR_WriteProcessMemory_8476 {
  strings:
    $key_8476 = { d3 04 [2] e1 26 [2] e7 13 [2] c9 13 [2] f6 0f }

  condition:
    any of them
}