rule TTP_XOR_WriteProcessMemory_d330 {
  strings:
    $key_d330 = { 84 42 [2] b6 60 [2] b0 55 [2] 9e 55 [2] a1 49 }

  condition:
    any of them
}