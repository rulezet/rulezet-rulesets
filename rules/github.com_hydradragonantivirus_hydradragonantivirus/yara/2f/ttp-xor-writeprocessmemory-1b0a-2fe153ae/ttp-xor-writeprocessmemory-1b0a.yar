rule TTP_XOR_WriteProcessMemory_1b0a {
  strings:
    $key_1b0a = { 4c 78 [2] 7e 5a [2] 78 6f [2] 56 6f [2] 69 73 }

  condition:
    any of them
}