rule TTP_XOR_WriteProcessMemory_c137 {
  strings:
    $key_c137 = { 96 45 [2] a4 67 [2] a2 52 [2] 8c 52 [2] b3 4e }

  condition:
    any of them
}