rule TTP_XOR_WriteProcessMemory_db74 {
  strings:
    $key_db74 = { 8c 06 [2] be 24 [2] b8 11 [2] 96 11 [2] a9 0d }

  condition:
    any of them
}