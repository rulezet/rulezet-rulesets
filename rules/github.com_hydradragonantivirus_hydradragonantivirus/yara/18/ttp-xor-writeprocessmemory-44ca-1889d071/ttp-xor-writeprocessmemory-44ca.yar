rule TTP_XOR_WriteProcessMemory_44ca {
  strings:
    $key_44ca = { 13 b8 [2] 21 9a [2] 27 af [2] 09 af [2] 36 b3 }

  condition:
    any of them
}