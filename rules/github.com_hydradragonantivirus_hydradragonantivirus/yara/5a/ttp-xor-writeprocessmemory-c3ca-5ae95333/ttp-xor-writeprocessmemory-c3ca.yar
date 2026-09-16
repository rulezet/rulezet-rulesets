rule TTP_XOR_WriteProcessMemory_c3ca {
  strings:
    $key_c3ca = { 94 b8 [2] a6 9a [2] a0 af [2] 8e af [2] b1 b3 }

  condition:
    any of them
}