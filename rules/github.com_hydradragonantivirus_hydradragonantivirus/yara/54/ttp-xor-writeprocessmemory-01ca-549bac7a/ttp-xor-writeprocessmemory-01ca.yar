rule TTP_XOR_WriteProcessMemory_01ca {
  strings:
    $key_01ca = { 56 b8 [2] 64 9a [2] 62 af [2] 4c af [2] 73 b3 }

  condition:
    any of them
}