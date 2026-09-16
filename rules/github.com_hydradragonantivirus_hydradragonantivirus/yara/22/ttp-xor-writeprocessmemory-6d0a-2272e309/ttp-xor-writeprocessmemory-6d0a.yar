rule TTP_XOR_WriteProcessMemory_6d0a {
  strings:
    $key_6d0a = { 3a 78 [2] 08 5a [2] 0e 6f [2] 20 6f [2] 1f 73 }

  condition:
    any of them
}