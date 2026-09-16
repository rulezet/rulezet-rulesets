rule TTP_XOR_WriteProcessMemory_ddb5 {
  strings:
    $key_ddb5 = { 8a c7 [2] b8 e5 [2] be d0 [2] 90 d0 [2] af cc }

  condition:
    any of them
}