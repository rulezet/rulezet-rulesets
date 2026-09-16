rule TTP_XOR_WriteProcessMemory_bcfb {
  strings:
    $key_bcfb = { eb 89 [2] d9 ab [2] df 9e [2] f1 9e [2] ce 82 }

  condition:
    any of them
}