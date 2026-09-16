rule TTP_XOR_WriteProcessMemory_712a {
  strings:
    $key_712a = { 26 58 [2] 14 7a [2] 12 4f [2] 3c 4f [2] 03 53 }

  condition:
    any of them
}