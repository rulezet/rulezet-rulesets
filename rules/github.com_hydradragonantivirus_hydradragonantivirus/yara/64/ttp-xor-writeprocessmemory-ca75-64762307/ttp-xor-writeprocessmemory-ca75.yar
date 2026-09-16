rule TTP_XOR_WriteProcessMemory_ca75 {
  strings:
    $key_ca75 = { 9d 07 [2] af 25 [2] a9 10 [2] 87 10 [2] b8 0c }

  condition:
    any of them
}