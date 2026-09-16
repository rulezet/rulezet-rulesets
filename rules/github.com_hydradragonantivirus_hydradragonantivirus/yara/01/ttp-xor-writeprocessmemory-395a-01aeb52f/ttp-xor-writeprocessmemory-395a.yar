rule TTP_XOR_WriteProcessMemory_395a {
  strings:
    $key_395a = { 6e 28 [2] 5c 0a [2] 5a 3f [2] 74 3f [2] 4b 23 }

  condition:
    any of them
}