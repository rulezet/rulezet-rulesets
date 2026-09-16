rule TTP_XOR_WriteProcessMemory_bbe6 {
  strings:
    $key_bbe6 = { ec 94 [2] de b6 [2] d8 83 [2] f6 83 [2] c9 9f }

  condition:
    any of them
}