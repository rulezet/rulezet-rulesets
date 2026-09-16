rule TTP_XOR_WriteProcessMemory_868d {
  strings:
    $key_868d = { d1 ff [2] e3 dd [2] e5 e8 [2] cb e8 [2] f4 f4 }

  condition:
    any of them
}