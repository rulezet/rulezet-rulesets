rule TTP_XOR_WriteProcessMemory_205a {
  strings:
    $key_205a = { 77 28 [2] 45 0a [2] 43 3f [2] 6d 3f [2] 52 23 }

  condition:
    any of them
}