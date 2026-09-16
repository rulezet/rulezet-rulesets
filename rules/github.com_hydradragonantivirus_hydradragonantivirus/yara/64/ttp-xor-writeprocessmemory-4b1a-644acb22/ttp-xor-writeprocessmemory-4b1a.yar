rule TTP_XOR_WriteProcessMemory_4b1a {
  strings:
    $key_4b1a = { 1c 68 [2] 2e 4a [2] 28 7f [2] 06 7f [2] 39 63 }

  condition:
    any of them
}