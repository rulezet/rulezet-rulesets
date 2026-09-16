rule TTP_XOR_WriteProcessMemory_0d5a {
  strings:
    $key_0d5a = { 5a 28 [2] 68 0a [2] 6e 3f [2] 40 3f [2] 7f 23 }

  condition:
    any of them
}