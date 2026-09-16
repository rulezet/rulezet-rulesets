rule TTP_XOR_WriteProcessMemory_2c0f {
  strings:
    $key_2c0f = { 7b 7d [2] 49 5f [2] 4f 6a [2] 61 6a [2] 5e 76 }

  condition:
    any of them
}