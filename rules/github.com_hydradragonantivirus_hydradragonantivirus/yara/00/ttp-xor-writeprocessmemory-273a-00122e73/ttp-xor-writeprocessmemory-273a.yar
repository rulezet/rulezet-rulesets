rule TTP_XOR_WriteProcessMemory_273a {
  strings:
    $key_273a = { 70 48 [2] 42 6a [2] 44 5f [2] 6a 5f [2] 55 43 }

  condition:
    any of them
}