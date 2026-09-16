rule TTP_XOR_WriteProcessMemory_2c0d {
  strings:
    $key_2c0d = { 7b 7f [2] 49 5d [2] 4f 68 [2] 61 68 [2] 5e 74 }

  condition:
    any of them
}