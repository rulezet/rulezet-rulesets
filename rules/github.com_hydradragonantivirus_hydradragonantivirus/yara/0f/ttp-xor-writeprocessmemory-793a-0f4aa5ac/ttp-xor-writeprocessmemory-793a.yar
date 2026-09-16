rule TTP_XOR_WriteProcessMemory_793a {
  strings:
    $key_793a = { 2e 48 [2] 1c 6a [2] 1a 5f [2] 34 5f [2] 0b 43 }

  condition:
    any of them
}