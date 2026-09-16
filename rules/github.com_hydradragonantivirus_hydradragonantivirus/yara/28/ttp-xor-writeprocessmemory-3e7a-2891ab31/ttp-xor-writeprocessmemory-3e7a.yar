rule TTP_XOR_WriteProcessMemory_3e7a {
  strings:
    $key_3e7a = { 69 08 [2] 5b 2a [2] 5d 1f [2] 73 1f [2] 4c 03 }

  condition:
    any of them
}