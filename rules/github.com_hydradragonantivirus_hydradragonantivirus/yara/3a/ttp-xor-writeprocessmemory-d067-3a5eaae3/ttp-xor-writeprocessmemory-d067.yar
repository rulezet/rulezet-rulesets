rule TTP_XOR_WriteProcessMemory_d067 {
  strings:
    $key_d067 = { 87 15 [2] b5 37 [2] b3 02 [2] 9d 02 [2] a2 1e }

  condition:
    any of them
}