rule TTP_XOR_WriteProcessMemory_d124 {
  strings:
    $key_d124 = { 86 56 [2] b4 74 [2] b2 41 [2] 9c 41 [2] a3 5d }

  condition:
    any of them
}