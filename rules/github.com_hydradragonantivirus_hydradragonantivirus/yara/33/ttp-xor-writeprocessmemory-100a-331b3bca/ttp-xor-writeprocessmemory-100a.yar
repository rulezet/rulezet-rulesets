rule TTP_XOR_WriteProcessMemory_100a {
  strings:
    $key_100a = { 47 78 [2] 75 5a [2] 73 6f [2] 5d 6f [2] 62 73 }

  condition:
    any of them
}