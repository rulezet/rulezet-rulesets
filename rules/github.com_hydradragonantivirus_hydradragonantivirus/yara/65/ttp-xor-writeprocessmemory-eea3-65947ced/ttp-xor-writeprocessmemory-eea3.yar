rule TTP_XOR_WriteProcessMemory_eea3 {
  strings:
    $key_eea3 = { b9 d1 [2] 8b f3 [2] 8d c6 [2] a3 c6 [2] 9c da }

  condition:
    any of them
}