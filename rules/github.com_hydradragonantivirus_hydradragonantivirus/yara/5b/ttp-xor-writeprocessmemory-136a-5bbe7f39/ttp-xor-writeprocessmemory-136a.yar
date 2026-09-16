rule TTP_XOR_WriteProcessMemory_136a {
  strings:
    $key_136a = { 44 18 [2] 76 3a [2] 70 0f [2] 5e 0f [2] 61 13 }

  condition:
    any of them
}