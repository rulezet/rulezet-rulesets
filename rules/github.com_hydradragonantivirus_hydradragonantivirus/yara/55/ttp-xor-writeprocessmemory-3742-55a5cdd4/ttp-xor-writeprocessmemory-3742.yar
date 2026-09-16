rule TTP_XOR_WriteProcessMemory_3742 {
  strings:
    $key_3742 = { 60 30 [2] 52 12 [2] 54 27 [2] 7a 27 [2] 45 3b }

  condition:
    any of them
}