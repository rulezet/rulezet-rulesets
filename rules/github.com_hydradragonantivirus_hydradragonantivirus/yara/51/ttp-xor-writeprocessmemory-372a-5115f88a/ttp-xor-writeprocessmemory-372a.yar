rule TTP_XOR_WriteProcessMemory_372a {
  strings:
    $key_372a = { 60 58 [2] 52 7a [2] 54 4f [2] 7a 4f [2] 45 53 }

  condition:
    any of them
}