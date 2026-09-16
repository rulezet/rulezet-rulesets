rule TTP_XOR_WriteProcessMemory_c1ca {
  strings:
    $key_c1ca = { 96 b8 [2] a4 9a [2] a2 af [2] 8c af [2] b3 b3 }

  condition:
    any of them
}