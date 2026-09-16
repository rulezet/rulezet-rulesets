rule TTP_XOR_WriteProcessMemory_c723 {
  strings:
    $key_c723 = { 90 51 [2] a2 73 [2] a4 46 [2] 8a 46 [2] b5 5a }

  condition:
    any of them
}