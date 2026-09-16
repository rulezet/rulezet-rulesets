rule TTP_XOR_WriteProcessMemory_66ca {
  strings:
    $key_66ca = { 31 b8 [2] 03 9a [2] 05 af [2] 2b af [2] 14 b3 }

  condition:
    any of them
}