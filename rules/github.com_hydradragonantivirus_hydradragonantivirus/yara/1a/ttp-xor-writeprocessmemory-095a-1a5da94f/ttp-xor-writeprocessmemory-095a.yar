rule TTP_XOR_WriteProcessMemory_095a {
  strings:
    $key_095a = { 5e 28 [2] 6c 0a [2] 6a 3f [2] 44 3f [2] 7b 23 }

  condition:
    any of them
}