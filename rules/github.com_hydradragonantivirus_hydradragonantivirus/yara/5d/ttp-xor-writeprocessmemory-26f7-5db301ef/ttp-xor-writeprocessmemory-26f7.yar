rule TTP_XOR_WriteProcessMemory_26f7 {
  strings:
    $key_26f7 = { 71 85 [2] 43 a7 [2] 45 92 [2] 6b 92 [2] 54 8e }

  condition:
    any of them
}