rule TTP_XOR_WriteProcessMemory_135a {
  strings:
    $key_135a = { 44 28 [2] 76 0a [2] 70 3f [2] 5e 3f [2] 61 23 }

  condition:
    any of them
}