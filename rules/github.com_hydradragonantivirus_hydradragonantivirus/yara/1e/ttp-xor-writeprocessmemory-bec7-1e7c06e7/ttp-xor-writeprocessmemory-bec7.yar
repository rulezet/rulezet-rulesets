rule TTP_XOR_WriteProcessMemory_bec7 {
  strings:
    $key_bec7 = { e9 b5 [2] db 97 [2] dd a2 [2] f3 a2 [2] cc be }

  condition:
    any of them
}