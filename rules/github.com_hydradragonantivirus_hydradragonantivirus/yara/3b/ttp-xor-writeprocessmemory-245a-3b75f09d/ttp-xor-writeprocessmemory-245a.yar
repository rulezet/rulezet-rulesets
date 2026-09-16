rule TTP_XOR_WriteProcessMemory_245a {
  strings:
    $key_245a = { 73 28 [2] 41 0a [2] 47 3f [2] 69 3f [2] 56 23 }

  condition:
    any of them
}