rule TTP_XOR_WriteProcessMemory_08cd {
  strings:
    $key_08cd = { 5f bf [2] 6d 9d [2] 6b a8 [2] 45 a8 [2] 7a b4 }

  condition:
    any of them
}