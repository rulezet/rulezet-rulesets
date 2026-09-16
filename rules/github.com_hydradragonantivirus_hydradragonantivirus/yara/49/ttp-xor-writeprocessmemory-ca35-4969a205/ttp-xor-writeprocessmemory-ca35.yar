rule TTP_XOR_WriteProcessMemory_ca35 {
  strings:
    $key_ca35 = { 9d 47 [2] af 65 [2] a9 50 [2] 87 50 [2] b8 4c }

  condition:
    any of them
}