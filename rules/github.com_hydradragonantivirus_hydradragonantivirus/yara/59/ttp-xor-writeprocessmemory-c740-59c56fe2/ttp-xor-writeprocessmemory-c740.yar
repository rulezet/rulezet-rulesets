rule TTP_XOR_WriteProcessMemory_c740 {
  strings:
    $key_c740 = { 90 32 [2] a2 10 [2] a4 25 [2] 8a 25 [2] b5 39 }

  condition:
    any of them
}