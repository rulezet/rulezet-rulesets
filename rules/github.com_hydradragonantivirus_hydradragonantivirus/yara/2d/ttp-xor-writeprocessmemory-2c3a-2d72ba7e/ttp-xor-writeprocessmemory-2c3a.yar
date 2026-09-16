rule TTP_XOR_WriteProcessMemory_2c3a {
  strings:
    $key_2c3a = { 7b 48 [2] 49 6a [2] 4f 5f [2] 61 5f [2] 5e 43 }

  condition:
    any of them
}