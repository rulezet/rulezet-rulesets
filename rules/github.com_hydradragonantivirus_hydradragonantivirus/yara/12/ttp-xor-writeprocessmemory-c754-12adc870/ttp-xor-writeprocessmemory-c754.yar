rule TTP_XOR_WriteProcessMemory_c754 {
  strings:
    $key_c754 = { 90 26 [2] a2 04 [2] a4 31 [2] 8a 31 [2] b5 2d }

  condition:
    any of them
}