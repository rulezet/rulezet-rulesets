rule TTP_XOR_WriteProcessMemory_355a {
  strings:
    $key_355a = { 62 28 [2] 50 0a [2] 56 3f [2] 78 3f [2] 47 23 }

  condition:
    any of them
}