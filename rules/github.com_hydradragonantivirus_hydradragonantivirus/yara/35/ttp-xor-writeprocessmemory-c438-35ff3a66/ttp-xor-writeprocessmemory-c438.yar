rule TTP_XOR_WriteProcessMemory_c438 {
  strings:
    $key_c438 = { 93 4a [2] a1 68 [2] a7 5d [2] 89 5d [2] b6 41 }

  condition:
    any of them
}