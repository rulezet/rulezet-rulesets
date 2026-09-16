rule TTP_XOR_WriteProcessMemory_d374 {
  strings:
    $key_d374 = { 84 06 [2] b6 24 [2] b0 11 [2] 9e 11 [2] a1 0d }

  condition:
    any of them
}