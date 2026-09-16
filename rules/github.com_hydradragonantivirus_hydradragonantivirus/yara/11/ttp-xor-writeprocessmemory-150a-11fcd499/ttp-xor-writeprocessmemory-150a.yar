rule TTP_XOR_WriteProcessMemory_150a {
  strings:
    $key_150a = { 42 78 [2] 70 5a [2] 76 6f [2] 58 6f [2] 67 73 }

  condition:
    any of them
}