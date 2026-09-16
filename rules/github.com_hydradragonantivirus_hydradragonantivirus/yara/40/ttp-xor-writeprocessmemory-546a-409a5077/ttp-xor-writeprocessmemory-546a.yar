rule TTP_XOR_WriteProcessMemory_546a {
  strings:
    $key_546a = { 03 18 [2] 31 3a [2] 37 0f [2] 19 0f [2] 26 13 }

  condition:
    any of them
}