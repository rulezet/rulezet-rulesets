rule TTP_XOR_WriteProcessMemory_76ca {
  strings:
    $key_76ca = { 21 b8 [2] 13 9a [2] 15 af [2] 3b af [2] 04 b3 }

  condition:
    any of them
}