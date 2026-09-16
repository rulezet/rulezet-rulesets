rule TTP_XOR_WriteProcessMemory_617a {
  strings:
    $key_617a = { 36 08 [2] 04 2a [2] 02 1f [2] 2c 1f [2] 13 03 }

  condition:
    any of them
}