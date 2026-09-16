rule TTP_XOR_WriteProcessMemory_d547 {
  strings:
    $key_d547 = { 82 35 [2] b0 17 [2] b6 22 [2] 98 22 [2] a7 3e }

  condition:
    any of them
}