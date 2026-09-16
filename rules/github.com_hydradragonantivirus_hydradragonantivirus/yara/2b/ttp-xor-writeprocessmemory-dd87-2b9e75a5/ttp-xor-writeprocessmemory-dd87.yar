rule TTP_XOR_WriteProcessMemory_dd87 {
  strings:
    $key_dd87 = { 8a f5 [2] b8 d7 [2] be e2 [2] 90 e2 [2] af fe }

  condition:
    any of them
}