rule TTP_XOR_WriteProcessMemory_8ea9 {
  strings:
    $key_8ea9 = { d9 db [2] eb f9 [2] ed cc [2] c3 cc [2] fc d0 }

  condition:
    any of them
}