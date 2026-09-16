rule TTP_XOR_WriteProcessMemory_762a {
  strings:
    $key_762a = { 21 58 [2] 13 7a [2] 15 4f [2] 3b 4f [2] 04 53 }

  condition:
    any of them
}