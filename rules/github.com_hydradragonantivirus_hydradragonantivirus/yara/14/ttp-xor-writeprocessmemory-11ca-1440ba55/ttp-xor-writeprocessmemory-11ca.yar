rule TTP_XOR_WriteProcessMemory_11ca {
  strings:
    $key_11ca = { 46 b8 [2] 74 9a [2] 72 af [2] 5c af [2] 63 b3 }

  condition:
    any of them
}