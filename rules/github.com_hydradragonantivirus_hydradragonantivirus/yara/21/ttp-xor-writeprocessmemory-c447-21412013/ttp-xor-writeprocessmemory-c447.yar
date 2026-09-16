rule TTP_XOR_WriteProcessMemory_c447 {
  strings:
    $key_c447 = { 93 35 [2] a1 17 [2] a7 22 [2] 89 22 [2] b6 3e }

  condition:
    any of them
}