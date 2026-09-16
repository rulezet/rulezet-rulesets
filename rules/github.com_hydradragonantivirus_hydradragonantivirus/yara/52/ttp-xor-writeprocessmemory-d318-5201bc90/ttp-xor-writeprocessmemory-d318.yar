rule TTP_XOR_WriteProcessMemory_d318 {
  strings:
    $key_d318 = { 84 6a [2] b6 48 [2] b0 7d [2] 9e 7d [2] a1 61 }

  condition:
    any of them
}