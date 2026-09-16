rule TTP_XOR_WriteProcessMemory_c037 {
  strings:
    $key_c037 = { 97 45 [2] a5 67 [2] a3 52 [2] 8d 52 [2] b2 4e }

  condition:
    any of them
}