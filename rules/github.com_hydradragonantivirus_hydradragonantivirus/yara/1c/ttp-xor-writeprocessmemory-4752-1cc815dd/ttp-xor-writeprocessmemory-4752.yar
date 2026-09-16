rule TTP_XOR_WriteProcessMemory_4752 {
  strings:
    $key_4752 = { 10 20 [2] 22 02 [2] 24 37 [2] 0a 37 [2] 35 2b }

  condition:
    any of them
}