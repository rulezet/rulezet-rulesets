rule TTP_XOR_WriteProcessMemory_fac7 {
  strings:
    $key_fac7 = { ad b5 [2] 9f 97 [2] 99 a2 [2] b7 a2 [2] 88 be }

  condition:
    any of them
}