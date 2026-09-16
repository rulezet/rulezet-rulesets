rule TTP_XOR_WriteProcessMemory_24ca {
  strings:
    $key_24ca = { 73 b8 [2] 41 9a [2] 47 af [2] 69 af [2] 56 b3 }

  condition:
    any of them
}