rule TTP_XOR_WriteProcessMemory_c4ca {
  strings:
    $key_c4ca = { 93 b8 [2] a1 9a [2] a7 af [2] 89 af [2] b6 b3 }

  condition:
    any of them
}