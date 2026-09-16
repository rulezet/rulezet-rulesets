rule TTP_XOR_WriteProcessMemory_c637 {
  strings:
    $key_c637 = { 91 45 [2] a3 67 [2] a5 52 [2] 8b 52 [2] b4 4e }

  condition:
    any of them
}