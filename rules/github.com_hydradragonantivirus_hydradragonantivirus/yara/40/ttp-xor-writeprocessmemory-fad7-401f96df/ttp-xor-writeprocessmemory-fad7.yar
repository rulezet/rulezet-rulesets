rule TTP_XOR_WriteProcessMemory_fad7 {
  strings:
    $key_fad7 = { ad a5 [2] 9f 87 [2] 99 b2 [2] b7 b2 [2] 88 ae }

  condition:
    any of them
}