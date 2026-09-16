rule TTP_XOR_WriteProcessMemory_daa8 {
  strings:
    $key_daa8 = { 8d da [2] bf f8 [2] b9 cd [2] 97 cd [2] a8 d1 }

  condition:
    any of them
}