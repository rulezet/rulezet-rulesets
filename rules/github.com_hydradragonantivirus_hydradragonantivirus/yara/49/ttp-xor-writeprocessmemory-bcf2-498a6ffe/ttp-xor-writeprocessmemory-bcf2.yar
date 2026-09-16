rule TTP_XOR_WriteProcessMemory_bcf2 {
  strings:
    $key_bcf2 = { eb 80 [2] d9 a2 [2] df 97 [2] f1 97 [2] ce 8b }

  condition:
    any of them
}