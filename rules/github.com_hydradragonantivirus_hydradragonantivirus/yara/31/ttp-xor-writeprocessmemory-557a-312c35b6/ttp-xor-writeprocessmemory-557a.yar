rule TTP_XOR_WriteProcessMemory_557a {
  strings:
    $key_557a = { 02 08 [2] 30 2a [2] 36 1f [2] 18 1f [2] 27 03 }

  condition:
    any of them
}