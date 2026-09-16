rule TTP_XOR_WriteProcessMemory_732a {
  strings:
    $key_732a = { 24 58 [2] 16 7a [2] 10 4f [2] 3e 4f [2] 01 53 }

  condition:
    any of them
}