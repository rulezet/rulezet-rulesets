rule TTP_XOR_WriteProcessMemory_542a {
  strings:
    $key_542a = { 03 58 [2] 31 7a [2] 37 4f [2] 19 4f [2] 26 53 }

  condition:
    any of them
}