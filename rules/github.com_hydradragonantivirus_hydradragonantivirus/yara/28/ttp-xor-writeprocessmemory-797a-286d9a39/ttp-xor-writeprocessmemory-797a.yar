rule TTP_XOR_WriteProcessMemory_797a {
  strings:
    $key_797a = { 2e 08 [2] 1c 2a [2] 1a 1f [2] 34 1f [2] 0b 03 }

  condition:
    any of them
}