rule TTP_XOR_WriteProcessMemory_9d8d {
  strings:
    $key_9d8d = { ca ff [2] f8 dd [2] fe e8 [2] d0 e8 [2] ef f4 }

  condition:
    any of them
}