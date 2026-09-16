rule TTP_XOR_WriteProcessMemory_64ca {
  strings:
    $key_64ca = { 33 b8 [2] 01 9a [2] 07 af [2] 29 af [2] 16 b3 }

  condition:
    any of them
}