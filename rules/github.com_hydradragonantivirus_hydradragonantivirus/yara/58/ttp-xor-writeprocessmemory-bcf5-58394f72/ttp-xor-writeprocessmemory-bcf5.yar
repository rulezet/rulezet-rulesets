rule TTP_XOR_WriteProcessMemory_bcf5 {
  strings:
    $key_bcf5 = { eb 87 [2] d9 a5 [2] df 90 [2] f1 90 [2] ce 8c }

  condition:
    any of them
}