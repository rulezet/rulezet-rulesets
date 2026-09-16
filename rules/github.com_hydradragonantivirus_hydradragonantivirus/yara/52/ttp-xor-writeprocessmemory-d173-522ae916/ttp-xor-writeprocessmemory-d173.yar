rule TTP_XOR_WriteProcessMemory_d173 {
  strings:
    $key_d173 = { 86 01 [2] b4 23 [2] b2 16 [2] 9c 16 [2] a3 0a }

  condition:
    any of them
}