rule TTP_XOR_WriteProcessMemory_28c7 {
  strings:
    $key_28c7 = { 7f b5 [2] 4d 97 [2] 4b a2 [2] 65 a2 [2] 5a be }

  condition:
    any of them
}