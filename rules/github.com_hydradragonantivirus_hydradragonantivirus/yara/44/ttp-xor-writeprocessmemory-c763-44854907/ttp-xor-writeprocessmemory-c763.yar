rule TTP_XOR_WriteProcessMemory_c763 {
  strings:
    $key_c763 = { 90 11 [2] a2 33 [2] a4 06 [2] 8a 06 [2] b5 1a }

  condition:
    any of them
}