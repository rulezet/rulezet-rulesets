rule TTP_XOR_WriteProcessMemory_477a {
  strings:
    $key_477a = { 10 08 [2] 22 2a [2] 24 1f [2] 0a 1f [2] 35 03 }

  condition:
    any of them
}