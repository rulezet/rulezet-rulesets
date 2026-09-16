rule TTP_XOR_WriteProcessMemory_522a {
  strings:
    $key_522a = { 05 58 [2] 37 7a [2] 31 4f [2] 1f 4f [2] 20 53 }

  condition:
    any of them
}