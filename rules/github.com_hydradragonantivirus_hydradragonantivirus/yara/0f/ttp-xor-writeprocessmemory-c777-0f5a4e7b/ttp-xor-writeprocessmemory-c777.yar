rule TTP_XOR_WriteProcessMemory_c777 {
  strings:
    $key_c777 = { 90 05 [2] a2 27 [2] a4 12 [2] 8a 12 [2] b5 0e }

  condition:
    any of them
}