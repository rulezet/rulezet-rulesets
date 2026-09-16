rule TTP_XOR_WriteProcessMemory_caf2 {
  strings:
    $key_caf2 = { 9d 80 [2] af a2 [2] a9 97 [2] 87 97 [2] b8 8b }

  condition:
    any of them
}