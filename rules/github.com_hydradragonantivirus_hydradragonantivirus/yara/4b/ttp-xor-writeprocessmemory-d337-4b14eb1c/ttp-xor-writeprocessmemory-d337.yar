rule TTP_XOR_WriteProcessMemory_d337 {
  strings:
    $key_d337 = { 84 45 [2] b6 67 [2] b0 52 [2] 9e 52 [2] a1 4e }

  condition:
    any of them
}