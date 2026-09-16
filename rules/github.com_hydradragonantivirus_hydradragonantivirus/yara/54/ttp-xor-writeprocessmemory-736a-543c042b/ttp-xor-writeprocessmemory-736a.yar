rule TTP_XOR_WriteProcessMemory_736a {
  strings:
    $key_736a = { 24 18 [2] 16 3a [2] 10 0f [2] 3e 0f [2] 01 13 }

  condition:
    any of them
}