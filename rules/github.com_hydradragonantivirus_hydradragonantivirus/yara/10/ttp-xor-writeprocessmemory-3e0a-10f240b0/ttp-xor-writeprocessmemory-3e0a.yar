rule TTP_XOR_WriteProcessMemory_3e0a {
  strings:
    $key_3e0a = { 69 78 [2] 5b 5a [2] 5d 6f [2] 73 6f [2] 4c 73 }

  condition:
    any of them
}