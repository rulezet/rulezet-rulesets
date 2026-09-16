rule TTP_XOR_WriteProcessMemory_052a {
  strings:
    $key_052a = { 52 58 [2] 60 7a [2] 66 4f [2] 48 4f [2] 77 53 }

  condition:
    any of them
}