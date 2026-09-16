rule TTP_XOR_WriteProcessMemory_ddc1 {
  strings:
    $key_ddc1 = { 8a b3 [2] b8 91 [2] be a4 [2] 90 a4 [2] af b8 }

  condition:
    any of them
}