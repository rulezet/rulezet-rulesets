rule TTP_XOR_WriteProcessMemory_faa9 {
  strings:
    $key_faa9 = { ad db [2] 9f f9 [2] 99 cc [2] b7 cc [2] 88 d0 }

  condition:
    any of them
}