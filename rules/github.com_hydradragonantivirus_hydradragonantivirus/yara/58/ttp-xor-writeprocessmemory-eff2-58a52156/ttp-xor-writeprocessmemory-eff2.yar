rule TTP_XOR_WriteProcessMemory_eff2 {
  strings:
    $key_eff2 = { b8 80 [2] 8a a2 [2] 8c 97 [2] a2 97 [2] 9d 8b }

  condition:
    any of them
}