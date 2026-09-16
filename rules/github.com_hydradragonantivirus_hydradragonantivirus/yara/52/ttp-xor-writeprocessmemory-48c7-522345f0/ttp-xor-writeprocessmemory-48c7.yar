rule TTP_XOR_WriteProcessMemory_48c7 {
  strings:
    $key_48c7 = { 1f b5 [2] 2d 97 [2] 2b a2 [2] 05 a2 [2] 3a be }

  condition:
    any of them
}