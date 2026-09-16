rule TTP_XOR_WriteProcessMemory_0ccd {
  strings:
    $key_0ccd = { 5b bf [2] 69 9d [2] 6f a8 [2] 41 a8 [2] 7e b4 }

  condition:
    any of them
}