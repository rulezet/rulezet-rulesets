rule TTP_XOR_WriteProcessMemory_480a {
  strings:
    $key_480a = { 1f 78 [2] 2d 5a [2] 2b 6f [2] 05 6f [2] 3a 73 }

  condition:
    any of them
}