rule TTP_XOR_WriteProcessMemory_526a {
  strings:
    $key_526a = { 05 18 [2] 37 3a [2] 31 0f [2] 1f 0f [2] 20 13 }

  condition:
    any of them
}