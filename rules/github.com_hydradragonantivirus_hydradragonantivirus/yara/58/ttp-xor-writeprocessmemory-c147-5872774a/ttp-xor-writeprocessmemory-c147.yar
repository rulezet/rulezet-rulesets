rule TTP_XOR_WriteProcessMemory_c147 {
  strings:
    $key_c147 = { 96 35 [2] a4 17 [2] a2 22 [2] 8c 22 [2] b3 3e }

  condition:
    any of them
}