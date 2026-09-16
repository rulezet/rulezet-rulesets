rule TTP_XOR_WriteProcessMemory_016a {
  strings:
    $key_016a = { 56 18 [2] 64 3a [2] 62 0f [2] 4c 0f [2] 73 13 }

  condition:
    any of them
}