rule TTP_XOR_WriteProcessMemory_662a {
  strings:
    $key_662a = { 31 58 [2] 03 7a [2] 05 4f [2] 2b 4f [2] 14 53 }

  condition:
    any of them
}