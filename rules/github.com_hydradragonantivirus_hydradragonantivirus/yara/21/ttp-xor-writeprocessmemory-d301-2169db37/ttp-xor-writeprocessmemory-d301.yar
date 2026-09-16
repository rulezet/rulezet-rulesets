rule TTP_XOR_WriteProcessMemory_d301 {
  strings:
    $key_d301 = { 84 73 [2] b6 51 [2] b0 64 [2] 9e 64 [2] a1 78 }

  condition:
    any of them
}