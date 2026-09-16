rule TTP_XOR_WriteProcessMemory_fcc7 {
  strings:
    $key_fcc7 = { ab b5 [2] 99 97 [2] 9f a2 [2] b1 a2 [2] 8e be }

  condition:
    any of them
}