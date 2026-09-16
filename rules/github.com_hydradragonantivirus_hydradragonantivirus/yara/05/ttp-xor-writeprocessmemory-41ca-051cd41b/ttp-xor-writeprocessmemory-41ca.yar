rule TTP_XOR_WriteProcessMemory_41ca {
  strings:
    $key_41ca = { 16 b8 [2] 24 9a [2] 22 af [2] 0c af [2] 33 b3 }

  condition:
    any of them
}