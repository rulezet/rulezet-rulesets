rule TTP_XOR_WriteProcessMemory_d536 {
  strings:
    $key_d536 = { 82 44 [2] b0 66 [2] b6 53 [2] 98 53 [2] a7 4f }

  condition:
    any of them
}