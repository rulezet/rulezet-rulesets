rule TTP_XOR_WriteProcessMemory_7f1a {
  strings:
    $key_7f1a = { 28 68 [2] 1a 4a [2] 1c 7f [2] 32 7f [2] 0d 63 }

  condition:
    any of them
}