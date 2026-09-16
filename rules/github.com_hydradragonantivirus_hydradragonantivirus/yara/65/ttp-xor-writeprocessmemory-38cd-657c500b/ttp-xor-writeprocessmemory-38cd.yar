rule TTP_XOR_WriteProcessMemory_38cd {
  strings:
    $key_38cd = { 6f bf [2] 5d 9d [2] 5b a8 [2] 75 a8 [2] 4a b4 }

  condition:
    any of them
}