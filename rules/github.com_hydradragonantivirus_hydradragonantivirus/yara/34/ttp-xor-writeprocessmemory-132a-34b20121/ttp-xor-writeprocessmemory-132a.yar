rule TTP_XOR_WriteProcessMemory_132a {
  strings:
    $key_132a = { 44 58 [2] 76 7a [2] 70 4f [2] 5e 4f [2] 61 53 }

  condition:
    any of them
}