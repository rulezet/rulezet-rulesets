rule TTP_XOR_WriteProcessMemory_362a {
  strings:
    $key_362a = { 61 58 [2] 53 7a [2] 55 4f [2] 7b 4f [2] 44 53 }

  condition:
    any of them
}