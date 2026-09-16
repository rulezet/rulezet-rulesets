rule TTP_XOR_WriteProcessMemory_e4ca {
  strings:
    $key_e4ca = { b3 b8 [2] 81 9a [2] 87 af [2] a9 af [2] 96 b3 }

  condition:
    any of them
}