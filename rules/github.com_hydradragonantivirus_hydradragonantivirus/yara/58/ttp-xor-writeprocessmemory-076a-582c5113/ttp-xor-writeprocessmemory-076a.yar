rule TTP_XOR_WriteProcessMemory_076a {
  strings:
    $key_076a = { 50 18 [2] 62 3a [2] 64 0f [2] 4a 0f [2] 75 13 }

  condition:
    any of them
}