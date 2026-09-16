rule TTP_XOR_WriteProcessMemory_492a {
  strings:
    $key_492a = { 1e 58 [2] 2c 7a [2] 2a 4f [2] 04 4f [2] 3b 53 }

  condition:
    any of them
}