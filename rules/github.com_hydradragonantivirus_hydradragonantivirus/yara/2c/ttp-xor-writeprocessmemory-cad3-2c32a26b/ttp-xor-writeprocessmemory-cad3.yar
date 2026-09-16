rule TTP_XOR_WriteProcessMemory_cad3 {
  strings:
    $key_cad3 = { 9d a1 [2] af 83 [2] a9 b6 [2] 87 b6 [2] b8 aa }

  condition:
    any of them
}