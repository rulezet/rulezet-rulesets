rule TTP_XOR_WriteProcessMemory_730a {
  strings:
    $key_730a = { 24 78 [2] 16 5a [2] 10 6f [2] 3e 6f [2] 01 73 }

  condition:
    any of them
}