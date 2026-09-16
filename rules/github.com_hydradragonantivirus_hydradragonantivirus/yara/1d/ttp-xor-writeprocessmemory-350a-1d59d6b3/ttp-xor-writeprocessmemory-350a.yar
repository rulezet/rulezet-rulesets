rule TTP_XOR_WriteProcessMemory_350a {
  strings:
    $key_350a = { 62 78 [2] 50 5a [2] 56 6f [2] 78 6f [2] 47 73 }

  condition:
    any of them
}