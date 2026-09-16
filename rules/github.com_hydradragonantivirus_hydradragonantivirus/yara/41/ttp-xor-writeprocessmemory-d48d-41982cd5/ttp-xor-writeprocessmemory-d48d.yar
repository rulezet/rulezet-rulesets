rule TTP_XOR_WriteProcessMemory_d48d {
  strings:
    $key_d48d = { 83 ff [2] b1 dd [2] b7 e8 [2] 99 e8 [2] a6 f4 }

  condition:
    any of them
}