rule TTP_XOR_WriteProcessMemory_143a {
  strings:
    $key_143a = { 43 48 [2] 71 6a [2] 77 5f [2] 59 5f [2] 66 43 }

  condition:
    any of them
}