rule TTP_XOR_WriteProcessMemory_4724 {
  strings:
    $key_4724 = { 10 56 [2] 22 74 [2] 24 41 [2] 0a 41 [2] 35 5d }

  condition:
    any of them
}