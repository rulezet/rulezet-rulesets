rule TTP_XOR_WriteProcessMemory_056a {
  strings:
    $key_056a = { 52 18 [2] 60 3a [2] 66 0f [2] 48 0f [2] 77 13 }

  condition:
    any of them
}