rule TTP_XOR_WriteProcessMemory_114a {
  strings:
    $key_114a = { 46 38 [2] 74 1a [2] 72 2f [2] 5c 2f [2] 63 33 }

  condition:
    any of them
}