rule TTP_XOR_WriteProcessMemory_206a {
  strings:
    $key_206a = { 77 18 [2] 45 3a [2] 43 0f [2] 6d 0f [2] 52 13 }

  condition:
    any of them
}