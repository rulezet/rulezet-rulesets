rule TTP_XOR_WriteProcessMemory_51ca {
  strings:
    $key_51ca = { 06 b8 [2] 34 9a [2] 32 af [2] 1c af [2] 23 b3 }

  condition:
    any of them
}