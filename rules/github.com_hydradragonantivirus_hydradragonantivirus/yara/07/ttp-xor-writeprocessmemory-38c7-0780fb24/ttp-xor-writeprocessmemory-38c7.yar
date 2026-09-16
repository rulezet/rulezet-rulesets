rule TTP_XOR_WriteProcessMemory_38c7 {
  strings:
    $key_38c7 = { 6f b5 [2] 5d 97 [2] 5b a2 [2] 75 a2 [2] 4a be }

  condition:
    any of them
}