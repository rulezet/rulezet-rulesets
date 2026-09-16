rule TTP_XOR_WriteProcessMemory_3502 {
  strings:
    $key_3502 = { 62 70 [2] 50 52 [2] 56 67 [2] 78 67 [2] 47 7b }

  condition:
    any of them
}