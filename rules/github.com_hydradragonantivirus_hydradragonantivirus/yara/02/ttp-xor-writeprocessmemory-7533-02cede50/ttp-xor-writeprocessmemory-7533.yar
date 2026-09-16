rule TTP_XOR_WriteProcessMemory_7533 {
  strings:
    $key_7533 = { 22 41 [2] 10 63 [2] 16 56 [2] 38 56 [2] 07 4a }

  condition:
    any of them
}