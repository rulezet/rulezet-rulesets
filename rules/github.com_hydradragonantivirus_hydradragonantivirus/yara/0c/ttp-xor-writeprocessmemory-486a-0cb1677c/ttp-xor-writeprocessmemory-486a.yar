rule TTP_XOR_WriteProcessMemory_486a {
  strings:
    $key_486a = { 1f 18 [2] 2d 3a [2] 2b 0f [2] 05 0f [2] 3a 13 }

  condition:
    any of them
}