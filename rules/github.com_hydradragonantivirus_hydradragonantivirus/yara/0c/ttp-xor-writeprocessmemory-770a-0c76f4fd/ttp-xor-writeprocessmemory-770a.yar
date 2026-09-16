rule TTP_XOR_WriteProcessMemory_770a {
  strings:
    $key_770a = { 20 78 [2] 12 5a [2] 14 6f [2] 3a 6f [2] 05 73 }

  condition:
    any of them
}