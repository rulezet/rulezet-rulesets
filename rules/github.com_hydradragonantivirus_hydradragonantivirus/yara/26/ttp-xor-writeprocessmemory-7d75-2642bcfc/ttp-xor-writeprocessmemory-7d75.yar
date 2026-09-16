rule TTP_XOR_WriteProcessMemory_7d75 {
  strings:
    $key_7d75 = { 2a 07 [2] 18 25 [2] 1e 10 [2] 30 10 [2] 0f 0c }

  condition:
    any of them
}