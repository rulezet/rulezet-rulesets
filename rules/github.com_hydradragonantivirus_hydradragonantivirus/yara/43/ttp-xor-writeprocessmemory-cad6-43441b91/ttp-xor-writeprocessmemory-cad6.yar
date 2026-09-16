rule TTP_XOR_WriteProcessMemory_cad6 {
  strings:
    $key_cad6 = { 9d a4 [2] af 86 [2] a9 b3 [2] 87 b3 [2] b8 af }

  condition:
    any of them
}