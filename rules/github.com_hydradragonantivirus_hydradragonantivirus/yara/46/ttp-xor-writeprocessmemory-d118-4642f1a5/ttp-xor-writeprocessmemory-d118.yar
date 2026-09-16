rule TTP_XOR_WriteProcessMemory_d118 {
  strings:
    $key_d118 = { 86 6a [2] b4 48 [2] b2 7d [2] 9c 7d [2] a3 61 }

  condition:
    any of them
}