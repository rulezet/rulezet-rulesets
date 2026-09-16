rule TTP_XOR_WriteProcessMemory_3f7a {
  strings:
    $key_3f7a = { 68 08 [2] 5a 2a [2] 5c 1f [2] 72 1f [2] 4d 03 }

  condition:
    any of them
}