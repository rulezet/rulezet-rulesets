rule TTP_XOR_WriteProcessMemory_acd0 {
  strings:
    $key_acd0 = { fb a2 [2] c9 80 [2] cf b5 [2] e1 b5 [2] de a9 }

  condition:
    any of them
}