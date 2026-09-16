rule TTP_XOR_WriteProcessMemory_0c5a {
  strings:
    $key_0c5a = { 5b 28 [2] 69 0a [2] 6f 3f [2] 41 3f [2] 7e 23 }

  condition:
    any of them
}