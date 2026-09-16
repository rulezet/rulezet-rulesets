rule TTP_XOR_WriteProcessMemory_3a0a {
  strings:
    $key_3a0a = { 6d 78 [2] 5f 5a [2] 59 6f [2] 77 6f [2] 48 73 }

  condition:
    any of them
}