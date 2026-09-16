rule TTP_XOR_WriteProcessMemory_0d2a {
  strings:
    $key_0d2a = { 5a 58 [2] 68 7a [2] 6e 4f [2] 40 4f [2] 7f 53 }

  condition:
    any of them
}