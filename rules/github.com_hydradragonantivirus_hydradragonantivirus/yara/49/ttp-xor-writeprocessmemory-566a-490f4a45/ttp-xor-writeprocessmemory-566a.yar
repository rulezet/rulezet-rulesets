rule TTP_XOR_WriteProcessMemory_566a {
  strings:
    $key_566a = { 01 18 [2] 33 3a [2] 35 0f [2] 1b 0f [2] 24 13 }

  condition:
    any of them
}