rule TTP_XOR_WriteProcessMemory_d064 {
  strings:
    $key_d064 = { 87 16 [2] b5 34 [2] b3 01 [2] 9d 01 [2] a2 1d }

  condition:
    any of them
}