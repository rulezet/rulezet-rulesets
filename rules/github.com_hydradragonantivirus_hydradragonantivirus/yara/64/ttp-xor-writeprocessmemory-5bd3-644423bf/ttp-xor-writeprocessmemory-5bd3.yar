rule TTP_XOR_WriteProcessMemory_5bd3 {
  strings:
    $key_5bd3 = { 0c a1 [2] 3e 83 [2] 38 b6 [2] 16 b6 [2] 29 aa }

  condition:
    any of them
}