rule TTP_XOR_WriteProcessMemory_487a {
  strings:
    $key_487a = { 1f 08 [2] 2d 2a [2] 2b 1f [2] 05 1f [2] 3a 03 }

  condition:
    any of them
}