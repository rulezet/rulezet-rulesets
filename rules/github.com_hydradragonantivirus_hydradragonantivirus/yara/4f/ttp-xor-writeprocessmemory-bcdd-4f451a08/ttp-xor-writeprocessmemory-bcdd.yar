rule TTP_XOR_WriteProcessMemory_bcdd {
  strings:
    $key_bcdd = { eb af [2] d9 8d [2] df b8 [2] f1 b8 [2] ce a4 }

  condition:
    any of them
}