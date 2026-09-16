rule TTP_XOR_WriteProcessMemory_7d7a {
  strings:
    $key_7d7a = { 2a 08 [2] 18 2a [2] 1e 1f [2] 30 1f [2] 0f 03 }

  condition:
    any of them
}