rule TTP_XOR_WriteProcessMemory_212a {
  strings:
    $key_212a = { 76 58 [2] 44 7a [2] 42 4f [2] 6c 4f [2] 53 53 }

  condition:
    any of them
}