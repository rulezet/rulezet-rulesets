rule TTP_XOR_WriteProcessMemory_ecc7 {
  strings:
    $key_ecc7 = { bb b5 [2] 89 97 [2] 8f a2 [2] a1 a2 [2] 9e be }

  condition:
    any of them
}