rule TTP_XOR_WriteProcessMemory_2c7a {
  strings:
    $key_2c7a = { 7b 08 [2] 49 2a [2] 4f 1f [2] 61 1f [2] 5e 03 }

  condition:
    any of them
}