rule TTP_XOR_WriteProcessMemory_36ca {
  strings:
    $key_36ca = { 61 b8 [2] 53 9a [2] 55 af [2] 7b af [2] 44 b3 }

  condition:
    any of them
}