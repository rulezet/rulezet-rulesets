rule TTP_XOR_WriteProcessMemory_2f0a {
  strings:
    $key_2f0a = { 78 78 [2] 4a 5a [2] 4c 6f [2] 62 6f [2] 5d 73 }

  condition:
    any of them
}