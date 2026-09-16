rule TTP_XOR_WriteProcessMemory_653a {
  strings:
    $key_653a = { 32 48 [2] 00 6a [2] 06 5f [2] 28 5f [2] 17 43 }

  condition:
    any of them
}