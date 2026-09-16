rule TTP_XOR_WriteProcessMemory_7d1a {
  strings:
    $key_7d1a = { 2a 68 [2] 18 4a [2] 1e 7f [2] 30 7f [2] 0f 63 }

  condition:
    any of them
}