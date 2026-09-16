rule TTP_XOR_WriteProcessMemory_116a {
  strings:
    $key_116a = { 46 18 [2] 74 3a [2] 72 0f [2] 5c 0f [2] 63 13 }

  condition:
    any of them
}