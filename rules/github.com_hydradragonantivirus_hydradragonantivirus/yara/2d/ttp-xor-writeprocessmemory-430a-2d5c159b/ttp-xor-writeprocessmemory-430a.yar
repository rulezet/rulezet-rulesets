rule TTP_XOR_WriteProcessMemory_430a {
  strings:
    $key_430a = { 14 78 [2] 26 5a [2] 20 6f [2] 0e 6f [2] 31 73 }

  condition:
    any of them
}