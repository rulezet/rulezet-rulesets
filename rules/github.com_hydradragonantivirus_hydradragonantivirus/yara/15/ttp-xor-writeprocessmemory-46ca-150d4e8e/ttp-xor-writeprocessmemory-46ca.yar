rule TTP_XOR_WriteProcessMemory_46ca {
  strings:
    $key_46ca = { 11 b8 [2] 23 9a [2] 25 af [2] 0b af [2] 34 b3 }

  condition:
    any of them
}