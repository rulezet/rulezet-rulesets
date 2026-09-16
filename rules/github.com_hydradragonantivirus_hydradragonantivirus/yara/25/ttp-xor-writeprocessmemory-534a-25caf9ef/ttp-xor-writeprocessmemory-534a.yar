rule TTP_XOR_WriteProcessMemory_534a {
  strings:
    $key_534a = { 04 38 [2] 36 1a [2] 30 2f [2] 1e 2f [2] 21 33 }

  condition:
    any of them
}