rule TTP_XOR_WriteProcessMemory_50ca {
  strings:
    $key_50ca = { 07 b8 [2] 35 9a [2] 33 af [2] 1d af [2] 22 b3 }

  condition:
    any of them
}