rule TTP_XOR_WriteProcessMemory_65ca {
  strings:
    $key_65ca = { 32 b8 [2] 00 9a [2] 06 af [2] 28 af [2] 17 b3 }

  condition:
    any of them
}