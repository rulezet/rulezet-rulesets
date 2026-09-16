rule TTP_XOR_WriteProcessMemory_746a {
  strings:
    $key_746a = { 23 18 [2] 11 3a [2] 17 0f [2] 39 0f [2] 06 13 }

  condition:
    any of them
}