rule TTP_XOR_WriteProcessMemory_2c2f {
  strings:
    $key_2c2f = { 7b 5d [2] 49 7f [2] 4f 4a [2] 61 4a [2] 5e 56 }

  condition:
    any of them
}