rule TTP_XOR_WriteProcessMemory_740a {
  strings:
    $key_740a = { 23 78 [2] 11 5a [2] 17 6f [2] 39 6f [2] 06 73 }

  condition:
    any of them
}