rule TTP_XOR_WriteProcessMemory_ade2 {
  strings:
    $key_ade2 = { fa 90 [2] c8 b2 [2] ce 87 [2] e0 87 [2] df 9b }

  condition:
    any of them
}