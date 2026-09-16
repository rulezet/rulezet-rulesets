rule TTP_XOR_WriteProcessMemory_bb01 {
  strings:
    $key_bb01 = { ec 73 [2] de 51 [2] d8 64 [2] f6 64 [2] c9 78 }

  condition:
    any of them
}