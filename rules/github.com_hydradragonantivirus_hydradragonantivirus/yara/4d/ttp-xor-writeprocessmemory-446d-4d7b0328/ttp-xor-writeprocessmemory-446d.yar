rule TTP_XOR_WriteProcessMemory_446d {
  strings:
    $key_446d = { 13 1f [2] 21 3d [2] 27 08 [2] 09 08 [2] 36 14 }

  condition:
    any of them
}