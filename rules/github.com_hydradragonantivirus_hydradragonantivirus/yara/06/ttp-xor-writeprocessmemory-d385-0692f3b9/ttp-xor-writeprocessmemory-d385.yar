rule TTP_XOR_WriteProcessMemory_d385 {
  strings:
    $key_d385 = { 84 f7 [2] b6 d5 [2] b0 e0 [2] 9e e0 [2] a1 fc }

  condition:
    any of them
}