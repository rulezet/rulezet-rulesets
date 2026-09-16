rule TTP_XOR_WriteProcessMemory_070a {
  strings:
    $key_070a = { 50 78 [2] 62 5a [2] 64 6f [2] 4a 6f [2] 75 73 }

  condition:
    any of them
}