rule TTP_XOR_WriteProcessMemory_fac3 {
  strings:
    $key_fac3 = { ad b1 [2] 9f 93 [2] 99 a6 [2] b7 a6 [2] 88 ba }

  condition:
    any of them
}