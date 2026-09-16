rule TTP_XOR_WriteProcessMemory_bcec {
  strings:
    $key_bcec = { eb 9e [2] d9 bc [2] df 89 [2] f1 89 [2] ce 95 }

  condition:
    any of them
}