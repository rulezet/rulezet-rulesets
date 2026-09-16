rule TTP_XOR_WriteProcessMemory_3c0a {
  strings:
    $key_3c0a = { 6b 78 [2] 59 5a [2] 5f 6f [2] 71 6f [2] 4e 73 }

  condition:
    any of them
}