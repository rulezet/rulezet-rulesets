rule TTP_XOR_WriteProcessMemory_d338 {
  strings:
    $key_d338 = { 84 4a [2] b6 68 [2] b0 5d [2] 9e 5d [2] a1 41 }

  condition:
    any of them
}