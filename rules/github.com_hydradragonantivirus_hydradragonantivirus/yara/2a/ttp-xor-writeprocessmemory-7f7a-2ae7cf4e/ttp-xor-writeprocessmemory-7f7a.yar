rule TTP_XOR_WriteProcessMemory_7f7a {
  strings:
    $key_7f7a = { 28 08 [2] 1a 2a [2] 1c 1f [2] 32 1f [2] 0d 03 }

  condition:
    any of them
}