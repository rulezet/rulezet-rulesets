rule TTP_XOR_WriteProcessMemory_3174 {
  strings:
    $key_3174 = { 66 06 [2] 54 24 [2] 52 11 [2] 7c 11 [2] 43 0d }

  condition:
    any of them
}