rule TTP_XOR_WriteProcessMemory_2b6a {
  strings:
    $key_2b6a = { 7c 18 [2] 4e 3a [2] 48 0f [2] 66 0f [2] 59 13 }

  condition:
    any of them
}