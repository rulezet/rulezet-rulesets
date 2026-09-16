rule TTP_XOR_WriteProcessMemory_ca45 {
  strings:
    $key_ca45 = { 9d 37 [2] af 15 [2] a9 20 [2] 87 20 [2] b8 3c }

  condition:
    any of them
}