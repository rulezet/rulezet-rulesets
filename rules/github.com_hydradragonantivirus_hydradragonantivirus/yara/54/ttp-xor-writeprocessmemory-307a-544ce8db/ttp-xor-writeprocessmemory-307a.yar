rule TTP_XOR_WriteProcessMemory_307a {
  strings:
    $key_307a = { 67 08 [2] 55 2a [2] 53 1f [2] 7d 1f [2] 42 03 }

  condition:
    any of them
}