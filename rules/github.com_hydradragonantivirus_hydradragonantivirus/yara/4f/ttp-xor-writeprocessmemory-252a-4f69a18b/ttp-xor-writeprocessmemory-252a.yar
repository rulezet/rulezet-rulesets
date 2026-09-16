rule TTP_XOR_WriteProcessMemory_252a {
  strings:
    $key_252a = { 72 58 [2] 40 7a [2] 46 4f [2] 68 4f [2] 57 53 }

  condition:
    any of them
}