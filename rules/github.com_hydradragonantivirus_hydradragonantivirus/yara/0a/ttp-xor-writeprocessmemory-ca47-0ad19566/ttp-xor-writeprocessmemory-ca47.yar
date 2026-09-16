rule TTP_XOR_WriteProcessMemory_ca47 {
  strings:
    $key_ca47 = { 9d 35 [2] af 17 [2] a9 22 [2] 87 22 [2] b8 3e }

  condition:
    any of them
}