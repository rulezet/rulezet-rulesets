rule TTP_XOR_WriteProcessMemory_73ca {
  strings:
    $key_73ca = { 24 b8 [2] 16 9a [2] 10 af [2] 3e af [2] 01 b3 }

  condition:
    any of them
}