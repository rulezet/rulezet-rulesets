rule TTP_XOR_WriteProcessMemory_251a {
  strings:
    $key_251a = { 72 68 [2] 40 4a [2] 46 7f [2] 68 7f [2] 57 63 }

  condition:
    any of them
}