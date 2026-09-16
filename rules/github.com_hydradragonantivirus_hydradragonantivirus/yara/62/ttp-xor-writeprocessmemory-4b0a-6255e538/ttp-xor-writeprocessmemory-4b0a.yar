rule TTP_XOR_WriteProcessMemory_4b0a {
  strings:
    $key_4b0a = { 1c 78 [2] 2e 5a [2] 28 6f [2] 06 6f [2] 39 73 }

  condition:
    any of them
}