rule TTP_XOR_WriteProcessMemory_2232 {
  strings:
    $key_2232 = { 75 40 [2] 47 62 [2] 41 57 [2] 6f 57 [2] 50 4b }

  condition:
    any of them
}