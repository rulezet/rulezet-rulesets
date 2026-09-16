rule TTP_XOR_WriteProcessMemory_200a {
  strings:
    $key_200a = { 77 78 [2] 45 5a [2] 43 6f [2] 6d 6f [2] 52 73 }

  condition:
    any of them
}