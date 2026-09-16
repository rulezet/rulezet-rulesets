rule TTP_XOR_WriteProcessMemory_11ce {
  strings:
    $key_11ce = { 46 bc [2] 74 9e [2] 72 ab [2] 5c ab [2] 63 b7 }

  condition:
    any of them
}