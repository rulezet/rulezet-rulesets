rule TTP_XOR_WriteProcessMemory_bcf9 {
  strings:
    $key_bcf9 = { eb 8b [2] d9 a9 [2] df 9c [2] f1 9c [2] ce 80 }

  condition:
    any of them
}