rule TTP_XOR_WriteProcessMemory_271a {
  strings:
    $key_271a = { 70 68 [2] 42 4a [2] 44 7f [2] 6a 7f [2] 55 63 }

  condition:
    any of them
}