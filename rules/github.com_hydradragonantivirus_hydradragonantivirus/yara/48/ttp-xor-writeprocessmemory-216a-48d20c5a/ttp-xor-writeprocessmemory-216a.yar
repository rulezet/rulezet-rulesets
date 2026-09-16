rule TTP_XOR_WriteProcessMemory_216a {
  strings:
    $key_216a = { 76 18 [2] 44 3a [2] 42 0f [2] 6c 0f [2] 53 13 }

  condition:
    any of them
}