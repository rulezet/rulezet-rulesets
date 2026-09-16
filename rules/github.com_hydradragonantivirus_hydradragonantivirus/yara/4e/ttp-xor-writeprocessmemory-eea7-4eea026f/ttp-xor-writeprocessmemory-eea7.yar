rule TTP_XOR_WriteProcessMemory_eea7 {
  strings:
    $key_eea7 = { b9 d5 [2] 8b f7 [2] 8d c2 [2] a3 c2 [2] 9c de }

  condition:
    any of them
}