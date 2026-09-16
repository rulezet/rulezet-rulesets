rule TTP_XOR_WriteProcessMemory_40ca {
  strings:
    $key_40ca = { 17 b8 [2] 25 9a [2] 23 af [2] 0d af [2] 32 b3 }

  condition:
    any of them
}