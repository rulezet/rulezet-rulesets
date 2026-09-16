rule TTP_XOR_WriteProcessMemory_167a {
  strings:
    $key_167a = { 41 08 [2] 73 2a [2] 75 1f [2] 5b 1f [2] 64 03 }

  condition:
    any of them
}