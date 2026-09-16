rule TTP_XOR_WriteProcessMemory_9fcb {
  strings:
    $key_9fcb = { c8 b9 [2] fa 9b [2] fc ae [2] d2 ae [2] ed b2 }

  condition:
    any of them
}