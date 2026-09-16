rule TTP_XOR_WriteProcessMemory_548a {
  strings:
    $key_548a = { 03 f8 [2] 31 da [2] 37 ef [2] 19 ef [2] 26 f3 }

  condition:
    any of them
}