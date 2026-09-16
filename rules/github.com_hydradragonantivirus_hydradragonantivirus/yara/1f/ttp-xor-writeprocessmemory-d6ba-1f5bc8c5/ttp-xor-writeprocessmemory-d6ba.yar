rule TTP_XOR_WriteProcessMemory_d6ba {
  strings:
    $key_d6ba = { 81 c8 [2] b3 ea [2] b5 df [2] 9b df [2] a4 c3 }

  condition:
    any of them
}