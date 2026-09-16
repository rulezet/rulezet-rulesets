rule TTP_XOR_WriteProcessMemory_300a {
  strings:
    $key_300a = { 67 78 [2] 55 5a [2] 53 6f [2] 7d 6f [2] 42 73 }

  condition:
    any of them
}