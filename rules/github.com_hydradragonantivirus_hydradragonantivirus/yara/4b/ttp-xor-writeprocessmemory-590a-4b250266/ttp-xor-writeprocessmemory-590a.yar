rule TTP_XOR_WriteProcessMemory_590a {
  strings:
    $key_590a = { 0e 78 [2] 3c 5a [2] 3a 6f [2] 14 6f [2] 2b 73 }

  condition:
    any of them
}