rule TTP_XOR_WriteProcessMemory_663a {
  strings:
    $key_663a = { 31 48 [2] 03 6a [2] 05 5f [2] 2b 5f [2] 14 43 }

  condition:
    any of them
}