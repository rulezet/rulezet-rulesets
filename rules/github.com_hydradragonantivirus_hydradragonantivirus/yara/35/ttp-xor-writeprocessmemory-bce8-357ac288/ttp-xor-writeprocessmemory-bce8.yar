rule TTP_XOR_WriteProcessMemory_bce8 {
  strings:
    $key_bce8 = { eb 9a [2] d9 b8 [2] df 8d [2] f1 8d [2] ce 91 }

  condition:
    any of them
}