rule TTP_XOR_WriteProcessMemory_7a0a {
  strings:
    $key_7a0a = { 2d 78 [2] 1f 5a [2] 19 6f [2] 37 6f [2] 08 73 }

  condition:
    any of them
}