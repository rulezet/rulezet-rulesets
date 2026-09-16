rule TTP_XOR_WriteProcessMemory_eea6 {
  strings:
    $key_eea6 = { b9 d4 [2] 8b f6 [2] 8d c3 [2] a3 c3 [2] 9c df }

  condition:
    any of them
}