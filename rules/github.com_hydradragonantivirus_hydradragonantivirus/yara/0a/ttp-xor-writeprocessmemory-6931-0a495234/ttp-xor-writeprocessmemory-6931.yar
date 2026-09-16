rule TTP_XOR_WriteProcessMemory_6931 {
  strings:
    $key_6931 = { 3e 43 [2] 0c 61 [2] 0a 54 [2] 24 54 [2] 1b 48 }

  condition:
    any of them
}