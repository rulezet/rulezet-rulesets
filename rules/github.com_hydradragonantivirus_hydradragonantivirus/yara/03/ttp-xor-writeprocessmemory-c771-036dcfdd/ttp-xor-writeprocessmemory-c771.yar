rule TTP_XOR_WriteProcessMemory_c771 {
  strings:
    $key_c771 = { 90 03 [2] a2 21 [2] a4 14 [2] 8a 14 [2] b5 08 }

  condition:
    any of them
}