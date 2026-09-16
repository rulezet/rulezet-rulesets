rule TTP_XOR_WriteProcessMemory_2174 {
  strings:
    $key_2174 = { 76 06 [2] 44 24 [2] 42 11 [2] 6c 11 [2] 53 0d }

  condition:
    any of them
}