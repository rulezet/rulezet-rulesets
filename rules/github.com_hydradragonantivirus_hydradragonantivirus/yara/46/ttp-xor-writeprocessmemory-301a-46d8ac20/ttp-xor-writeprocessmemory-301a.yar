rule TTP_XOR_WriteProcessMemory_301a {
  strings:
    $key_301a = { 67 68 [2] 55 4a [2] 53 7f [2] 7d 7f [2] 42 63 }

  condition:
    any of them
}