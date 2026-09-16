rule TTP_XOR_WriteProcessMemory_ca61 {
  strings:
    $key_ca61 = { 9d 13 [2] af 31 [2] a9 04 [2] 87 04 [2] b8 18 }

  condition:
    any of them
}