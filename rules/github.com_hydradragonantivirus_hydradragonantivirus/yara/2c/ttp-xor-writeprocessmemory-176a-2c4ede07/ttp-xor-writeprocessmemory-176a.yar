rule TTP_XOR_WriteProcessMemory_176a {
  strings:
    $key_176a = { 40 18 [2] 72 3a [2] 74 0f [2] 5a 0f [2] 65 13 }

  condition:
    any of them
}