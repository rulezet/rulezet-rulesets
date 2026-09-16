rule TTP_XOR_WriteProcessMemory_527a {
  strings:
    $key_527a = { 05 08 [2] 37 2a [2] 31 1f [2] 1f 1f [2] 20 03 }

  condition:
    any of them
}