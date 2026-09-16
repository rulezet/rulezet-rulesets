rule TTP_XOR_WriteProcessMemory_cadd {
  strings:
    $key_cadd = { 9d af [2] af 8d [2] a9 b8 [2] 87 b8 [2] b8 a4 }

  condition:
    any of them
}