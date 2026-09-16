rule TTP_XOR_WriteProcessMemory_184a {
  strings:
    $key_184a = { 4f 38 [2] 7d 1a [2] 7b 2f [2] 55 2f [2] 6a 33 }

  condition:
    any of them
}