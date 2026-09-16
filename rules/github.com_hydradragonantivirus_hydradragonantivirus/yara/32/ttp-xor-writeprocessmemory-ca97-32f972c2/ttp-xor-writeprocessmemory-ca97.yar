rule TTP_XOR_WriteProcessMemory_ca97 {
  strings:
    $key_ca97 = { 9d e5 [2] af c7 [2] a9 f2 [2] 87 f2 [2] b8 ee }

  condition:
    any of them
}