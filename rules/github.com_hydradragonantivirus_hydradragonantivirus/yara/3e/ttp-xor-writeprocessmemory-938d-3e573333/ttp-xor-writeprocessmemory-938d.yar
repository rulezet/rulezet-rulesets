rule TTP_XOR_WriteProcessMemory_938d {
  strings:
    $key_938d = { c4 ff [2] f6 dd [2] f0 e8 [2] de e8 [2] e1 f4 }

  condition:
    any of them
}