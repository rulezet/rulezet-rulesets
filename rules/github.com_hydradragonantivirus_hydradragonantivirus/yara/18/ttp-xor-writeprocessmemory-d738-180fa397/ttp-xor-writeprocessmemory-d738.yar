rule TTP_XOR_WriteProcessMemory_d738 {
  strings:
    $key_d738 = { 80 4a [2] b2 68 [2] b4 5d [2] 9a 5d [2] a5 41 }

  condition:
    any of them
}