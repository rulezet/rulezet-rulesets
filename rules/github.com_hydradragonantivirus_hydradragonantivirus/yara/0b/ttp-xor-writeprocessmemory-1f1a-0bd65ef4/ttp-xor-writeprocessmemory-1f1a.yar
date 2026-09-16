rule TTP_XOR_WriteProcessMemory_1f1a {
  strings:
    $key_1f1a = { 48 68 [2] 7a 4a [2] 7c 7f [2] 52 7f [2] 6d 63 }

  condition:
    any of them
}