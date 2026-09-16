rule TTP_XOR_WriteProcessMemory_2ccd {
  strings:
    $key_2ccd = { 7b bf [2] 49 9d [2] 4f a8 [2] 61 a8 [2] 5e b4 }

  condition:
    any of them
}