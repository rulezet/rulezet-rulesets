rule TTP_XOR_WriteProcessMemory_716a {
  strings:
    $key_716a = { 26 18 [2] 14 3a [2] 12 0f [2] 3c 0f [2] 03 13 }

  condition:
    any of them
}