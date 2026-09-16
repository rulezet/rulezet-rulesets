rule TTP_XOR_WriteProcessMemory_4fb8 {
  strings:
    $key_4fb8 = { 18 ca [2] 2a e8 [2] 2c dd [2] 02 dd [2] 3d c1 }

  condition:
    any of them
}