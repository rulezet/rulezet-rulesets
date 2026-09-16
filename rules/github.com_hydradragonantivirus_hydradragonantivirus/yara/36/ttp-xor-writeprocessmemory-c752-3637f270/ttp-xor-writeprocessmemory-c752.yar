rule TTP_XOR_WriteProcessMemory_c752 {
  strings:
    $key_c752 = { 90 20 [2] a2 02 [2] a4 37 [2] 8a 37 [2] b5 2b }

  condition:
    any of them
}