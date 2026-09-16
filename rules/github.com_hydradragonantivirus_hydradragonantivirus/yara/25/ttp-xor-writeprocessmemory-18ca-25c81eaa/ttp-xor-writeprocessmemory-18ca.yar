rule TTP_XOR_WriteProcessMemory_18ca {
  strings:
    $key_18ca = { 4f b8 [2] 7d 9a [2] 7b af [2] 55 af [2] 6a b3 }

  condition:
    any of them
}