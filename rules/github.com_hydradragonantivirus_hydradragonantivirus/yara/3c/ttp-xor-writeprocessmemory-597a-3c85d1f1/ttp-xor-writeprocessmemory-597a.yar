rule TTP_XOR_WriteProcessMemory_597a {
  strings:
    $key_597a = { 0e 08 [2] 3c 2a [2] 3a 1f [2] 14 1f [2] 2b 03 }

  condition:
    any of them
}