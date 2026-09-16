rule TTP_XOR_WriteProcessMemory_48cd {
  strings:
    $key_48cd = { 1f bf [2] 2d 9d [2] 2b a8 [2] 05 a8 [2] 3a b4 }

  condition:
    any of them
}