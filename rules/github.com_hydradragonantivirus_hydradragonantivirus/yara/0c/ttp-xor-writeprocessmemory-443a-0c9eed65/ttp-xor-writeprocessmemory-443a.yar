rule TTP_XOR_WriteProcessMemory_443a {
  strings:
    $key_443a = { 13 48 [2] 21 6a [2] 27 5f [2] 09 5f [2] 36 43 }

  condition:
    any of them
}