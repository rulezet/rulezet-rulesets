rule TTP_XOR_WriteProcessMemory_948d {
  strings:
    $key_948d = { c3 ff [2] f1 dd [2] f7 e8 [2] d9 e8 [2] e6 f4 }

  condition:
    any of them
}