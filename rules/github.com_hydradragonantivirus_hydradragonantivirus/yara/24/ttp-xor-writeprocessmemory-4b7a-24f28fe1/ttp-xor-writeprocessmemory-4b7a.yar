rule TTP_XOR_WriteProcessMemory_4b7a {
  strings:
    $key_4b7a = { 1c 08 [2] 2e 2a [2] 28 1f [2] 06 1f [2] 39 03 }

  condition:
    any of them
}