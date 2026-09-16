rule TTP_XOR_WriteProcessMemory_c5cd {
  strings:
    $key_c5cd = { 92 bf [2] a0 9d [2] a6 a8 [2] 88 a8 [2] b7 b4 }

  condition:
    any of them
}