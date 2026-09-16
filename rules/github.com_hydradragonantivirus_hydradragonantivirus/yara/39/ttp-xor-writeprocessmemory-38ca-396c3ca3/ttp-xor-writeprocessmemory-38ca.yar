rule TTP_XOR_WriteProcessMemory_38ca {
  strings:
    $key_38ca = { 6f b8 [2] 5d 9a [2] 5b af [2] 75 af [2] 4a b3 }

  condition:
    any of them
}