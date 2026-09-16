rule TTP_XOR_WriteProcessMemory_eac7 {
  strings:
    $key_eac7 = { bd b5 [2] 8f 97 [2] 89 a2 [2] a7 a2 [2] 98 be }

  condition:
    any of them
}