rule TTP_XOR_WriteProcessMemory_ddc6 {
  strings:
    $key_ddc6 = { 8a b4 [2] b8 96 [2] be a3 [2] 90 a3 [2] af bf }

  condition:
    any of them
}