rule TTP_XOR_WriteProcessMemory_18c7 {
  strings:
    $key_18c7 = { 4f b5 [2] 7d 97 [2] 7b a2 [2] 55 a2 [2] 6a be }

  condition:
    any of them
}