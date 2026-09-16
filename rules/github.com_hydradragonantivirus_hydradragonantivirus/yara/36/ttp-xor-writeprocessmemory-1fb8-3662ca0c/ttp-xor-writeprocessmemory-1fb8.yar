rule TTP_XOR_WriteProcessMemory_1fb8 {
  strings:
    $key_1fb8 = { 48 ca [2] 7a e8 [2] 7c dd [2] 52 dd [2] 6d c1 }

  condition:
    any of them
}