rule TTP_XOR_WriteProcessMemory_eea4 {
  strings:
    $key_eea4 = { b9 d6 [2] 8b f4 [2] 8d c1 [2] a3 c1 [2] 9c dd }

  condition:
    any of them
}