rule TTP_XOR_WriteProcessMemory_365a {
  strings:
    $key_365a = { 61 28 [2] 53 0a [2] 55 3f [2] 7b 3f [2] 44 23 }

  condition:
    any of them
}