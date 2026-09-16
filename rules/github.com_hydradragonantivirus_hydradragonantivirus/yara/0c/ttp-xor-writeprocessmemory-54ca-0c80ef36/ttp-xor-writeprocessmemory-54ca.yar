rule TTP_XOR_WriteProcessMemory_54ca {
  strings:
    $key_54ca = { 03 b8 [2] 31 9a [2] 37 af [2] 19 af [2] 26 b3 }

  condition:
    any of them
}