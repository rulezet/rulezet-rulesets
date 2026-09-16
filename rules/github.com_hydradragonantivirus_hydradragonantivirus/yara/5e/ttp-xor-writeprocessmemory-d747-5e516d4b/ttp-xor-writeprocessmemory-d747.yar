rule TTP_XOR_WriteProcessMemory_d747 {
  strings:
    $key_d747 = { 80 35 [2] b2 17 [2] b4 22 [2] 9a 22 [2] a5 3e }

  condition:
    any of them
}