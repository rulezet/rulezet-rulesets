rule TTP_XOR_WriteProcessMemory_c047 {
  strings:
    $key_c047 = { 97 35 [2] a5 17 [2] a3 22 [2] 8d 22 [2] b2 3e }

  condition:
    any of them
}