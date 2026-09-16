rule TTP_XOR_WriteProcessMemory_3e5a {
  strings:
    $key_3e5a = { 69 28 [2] 5b 0a [2] 5d 3f [2] 73 3f [2] 4c 23 }

  condition:
    any of them
}