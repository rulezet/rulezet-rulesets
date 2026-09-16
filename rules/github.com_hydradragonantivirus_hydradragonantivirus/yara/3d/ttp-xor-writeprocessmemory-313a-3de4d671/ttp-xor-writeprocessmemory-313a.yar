rule TTP_XOR_WriteProcessMemory_313a {
  strings:
    $key_313a = { 66 48 [2] 54 6a [2] 52 5f [2] 7c 5f [2] 43 43 }

  condition:
    any of them
}