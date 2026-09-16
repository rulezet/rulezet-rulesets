rule TTP_XOR_WriteProcessMemory_58cd {
  strings:
    $key_58cd = { 0f bf [2] 3d 9d [2] 3b a8 [2] 15 a8 [2] 2a b4 }

  condition:
    any of them
}