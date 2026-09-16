rule TTP_XOR_WriteProcessMemory_042a {
  strings:
    $key_042a = { 53 58 [2] 61 7a [2] 67 4f [2] 49 4f [2] 76 53 }

  condition:
    any of them
}