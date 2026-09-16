rule TTP_XOR_WriteProcessMemory_535a {
  strings:
    $key_535a = { 04 28 [2] 36 0a [2] 30 3f [2] 1e 3f [2] 21 23 }

  condition:
    any of them
}