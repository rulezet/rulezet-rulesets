rule TTP_XOR_WriteProcessMemory_6c43 {
  strings:
    $key_6c43 = { 3b 31 [2] 09 13 [2] 0f 26 [2] 21 26 [2] 1e 3a }

  condition:
    any of them
}