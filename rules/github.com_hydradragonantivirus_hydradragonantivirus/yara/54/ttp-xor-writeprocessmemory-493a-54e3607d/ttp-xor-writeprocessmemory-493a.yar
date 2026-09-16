rule TTP_XOR_WriteProcessMemory_493a {
  strings:
    $key_493a = { 1e 48 [2] 2c 6a [2] 2a 5f [2] 04 5f [2] 3b 43 }

  condition:
    any of them
}