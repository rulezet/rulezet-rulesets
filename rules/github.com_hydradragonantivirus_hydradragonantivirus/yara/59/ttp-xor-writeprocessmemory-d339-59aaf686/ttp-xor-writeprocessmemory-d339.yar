rule TTP_XOR_WriteProcessMemory_d339 {
  strings:
    $key_d339 = { 84 4b [2] b6 69 [2] b0 5c [2] 9e 5c [2] a1 40 }

  condition:
    any of them
}