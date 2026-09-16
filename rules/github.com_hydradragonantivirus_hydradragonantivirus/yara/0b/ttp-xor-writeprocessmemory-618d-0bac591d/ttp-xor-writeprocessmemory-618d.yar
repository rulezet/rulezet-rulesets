rule TTP_XOR_WriteProcessMemory_618d {
  strings:
    $key_618d = { 36 ff [2] 04 dd [2] 02 e8 [2] 2c e8 [2] 13 f4 }

  condition:
    any of them
}