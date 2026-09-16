rule TTP_XOR_WriteProcessMemory_5a6a {
  strings:
    $key_5a6a = { 0d 18 [2] 3f 3a [2] 39 0f [2] 17 0f [2] 28 13 }

  condition:
    any of them
}