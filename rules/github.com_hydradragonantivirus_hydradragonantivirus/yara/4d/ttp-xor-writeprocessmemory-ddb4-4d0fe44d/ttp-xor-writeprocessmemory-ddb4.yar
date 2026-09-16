rule TTP_XOR_WriteProcessMemory_ddb4 {
  strings:
    $key_ddb4 = { 8a c6 [2] b8 e4 [2] be d1 [2] 90 d1 [2] af cd }

  condition:
    any of them
}