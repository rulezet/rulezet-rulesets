rule TTP_XOR_WriteProcessMemory_111a {
  strings:
    $key_111a = { 46 68 [2] 74 4a [2] 72 7f [2] 5c 7f [2] 63 63 }

  condition:
    any of them
}