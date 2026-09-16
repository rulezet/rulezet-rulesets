rule TTP_XOR_WriteProcessMemory_2b5a {
  strings:
    $key_2b5a = { 7c 28 [2] 4e 0a [2] 48 3f [2] 66 3f [2] 59 23 }

  condition:
    any of them
}