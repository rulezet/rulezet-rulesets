rule TTP_XOR_WriteProcessMemory_ee32 {
  strings:
    $key_ee32 = { b9 40 [2] 8b 62 [2] 8d 57 [2] a3 57 [2] 9c 4b }

  condition:
    any of them
}