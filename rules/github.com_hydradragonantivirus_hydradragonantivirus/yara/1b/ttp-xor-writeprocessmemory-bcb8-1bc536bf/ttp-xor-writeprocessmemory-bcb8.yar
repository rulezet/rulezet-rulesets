rule TTP_XOR_WriteProcessMemory_bcb8 {
  strings:
    $key_bcb8 = { eb ca [2] d9 e8 [2] df dd [2] f1 dd [2] ce c1 }

  condition:
    any of them
}