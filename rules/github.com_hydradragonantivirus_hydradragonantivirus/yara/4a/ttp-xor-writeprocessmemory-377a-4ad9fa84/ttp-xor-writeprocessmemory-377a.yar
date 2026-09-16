rule TTP_XOR_WriteProcessMemory_377a {
  strings:
    $key_377a = { 60 08 [2] 52 2a [2] 54 1f [2] 7a 1f [2] 45 03 }

  condition:
    any of them
}