rule TTP_XOR_WriteProcessMemory_1e7a {
  strings:
    $key_1e7a = { 49 08 [2] 7b 2a [2] 7d 1f [2] 53 1f [2] 6c 03 }

  condition:
    any of them
}