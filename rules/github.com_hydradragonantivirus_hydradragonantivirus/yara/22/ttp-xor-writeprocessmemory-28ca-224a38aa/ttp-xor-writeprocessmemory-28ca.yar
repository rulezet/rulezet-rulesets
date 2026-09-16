rule TTP_XOR_WriteProcessMemory_28ca {
  strings:
    $key_28ca = { 7f b8 [2] 4d 9a [2] 4b af [2] 65 af [2] 5a b3 }

  condition:
    any of them
}