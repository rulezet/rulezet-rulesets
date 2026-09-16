rule TTP_XOR_WriteProcessMemory_8686 {
  strings:
    $key_8686 = { d1 f4 [2] e3 d6 [2] e5 e3 [2] cb e3 [2] f4 ff }

  condition:
    any of them
}