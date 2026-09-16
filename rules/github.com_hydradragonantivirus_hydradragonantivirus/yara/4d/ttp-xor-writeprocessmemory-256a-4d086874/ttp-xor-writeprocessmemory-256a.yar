rule TTP_XOR_WriteProcessMemory_256a {
  strings:
    $key_256a = { 72 18 [2] 40 3a [2] 46 0f [2] 68 0f [2] 57 13 }

  condition:
    any of them
}