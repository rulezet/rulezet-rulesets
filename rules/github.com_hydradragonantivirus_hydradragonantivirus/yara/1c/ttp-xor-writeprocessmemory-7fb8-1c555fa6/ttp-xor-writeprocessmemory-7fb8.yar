rule TTP_XOR_WriteProcessMemory_7fb8 {
  strings:
    $key_7fb8 = { 28 ca [2] 1a e8 [2] 1c dd [2] 32 dd [2] 0d c1 }

  condition:
    any of them
}