rule TTP_XOR_WriteProcessMemory_30c7 {
  strings:
    $key_30c7 = { 67 b5 [2] 55 97 [2] 53 a2 [2] 7d a2 [2] 42 be }

  condition:
    any of them
}