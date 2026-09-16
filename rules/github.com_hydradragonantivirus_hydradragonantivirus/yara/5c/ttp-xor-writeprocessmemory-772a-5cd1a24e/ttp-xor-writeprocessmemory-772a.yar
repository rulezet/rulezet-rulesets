rule TTP_XOR_WriteProcessMemory_772a {
  strings:
    $key_772a = { 20 58 [2] 12 7a [2] 14 4f [2] 3a 4f [2] 05 53 }

  condition:
    any of them
}