rule TTP_XOR_WriteProcessMemory_aac6 {
  strings:
    $key_aac6 = { fd b4 [2] cf 96 [2] c9 a3 [2] e7 a3 [2] d8 bf }

  condition:
    any of them
}