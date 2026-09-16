rule TTP_XOR_WriteProcessMemory_fccd {
  strings:
    $key_fccd = { ab bf [2] 99 9d [2] 9f a8 [2] b1 a8 [2] 8e b4 }

  condition:
    any of them
}