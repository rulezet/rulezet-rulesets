rule TTP_XOR_WriteProcessMemory_001a {
  strings:
    $key_001a = { 57 68 [2] 65 4a [2] 63 7f [2] 4d 7f [2] 72 63 }

  condition:
    any of them
}