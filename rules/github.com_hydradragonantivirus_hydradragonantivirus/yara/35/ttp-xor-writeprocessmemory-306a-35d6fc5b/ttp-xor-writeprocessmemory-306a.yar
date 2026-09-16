rule TTP_XOR_WriteProcessMemory_306a {
  strings:
    $key_306a = { 67 18 [2] 55 3a [2] 53 0f [2] 7d 0f [2] 42 13 }

  condition:
    any of them
}