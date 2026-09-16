rule TTP_XOR_WriteProcessMemory_ca17 {
  strings:
    $key_ca17 = { 9d 65 [2] af 47 [2] a9 72 [2] 87 72 [2] b8 6e }

  condition:
    any of them
}