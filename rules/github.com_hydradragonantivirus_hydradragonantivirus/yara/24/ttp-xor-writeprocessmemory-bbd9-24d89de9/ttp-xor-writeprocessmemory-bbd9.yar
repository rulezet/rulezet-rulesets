rule TTP_XOR_WriteProcessMemory_bbd9 {
  strings:
    $key_bbd9 = { ec ab [2] de 89 [2] d8 bc [2] f6 bc [2] c9 a0 }

  condition:
    any of them
}