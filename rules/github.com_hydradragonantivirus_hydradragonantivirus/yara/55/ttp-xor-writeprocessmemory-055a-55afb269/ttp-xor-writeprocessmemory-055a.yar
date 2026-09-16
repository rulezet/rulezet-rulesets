rule TTP_XOR_WriteProcessMemory_055a {
  strings:
    $key_055a = { 52 28 [2] 60 0a [2] 66 3f [2] 48 3f [2] 77 23 }

  condition:
    any of them
}