rule TTP_XOR_WriteProcessMemory_63ca {
  strings:
    $key_63ca = { 34 b8 [2] 06 9a [2] 00 af [2] 2e af [2] 11 b3 }

  condition:
    any of them
}