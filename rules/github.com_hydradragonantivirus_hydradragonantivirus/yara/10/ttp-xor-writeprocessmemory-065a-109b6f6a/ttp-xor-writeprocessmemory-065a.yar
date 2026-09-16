rule TTP_XOR_WriteProcessMemory_065a {
  strings:
    $key_065a = { 51 28 [2] 63 0a [2] 65 3f [2] 4b 3f [2] 74 23 }

  condition:
    any of them
}