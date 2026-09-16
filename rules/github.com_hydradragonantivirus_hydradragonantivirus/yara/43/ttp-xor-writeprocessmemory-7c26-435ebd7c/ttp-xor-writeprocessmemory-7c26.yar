rule TTP_XOR_WriteProcessMemory_7c26 {
  strings:
    $key_7c26 = { 2b 54 [2] 19 76 [2] 1f 43 [2] 31 43 [2] 0e 5f }

  condition:
    any of them
}