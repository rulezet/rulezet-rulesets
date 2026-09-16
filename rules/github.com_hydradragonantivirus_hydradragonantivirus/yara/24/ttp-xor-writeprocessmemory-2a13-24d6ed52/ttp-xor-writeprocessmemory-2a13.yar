rule TTP_XOR_WriteProcessMemory_2a13 {
  strings:
    $key_2a13 = { 7d 61 [2] 4f 43 [2] 49 76 [2] 67 76 [2] 58 6a }

  condition:
    any of them
}