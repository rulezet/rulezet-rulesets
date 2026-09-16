rule TTP_XOR_WriteProcessMemory_e8c7 {
  strings:
    $key_e8c7 = { bf b5 [2] 8d 97 [2] 8b a2 [2] a5 a2 [2] 9a be }

  condition:
    any of them
}