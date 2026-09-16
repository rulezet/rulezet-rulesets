rule TTP_XOR_WriteProcessMemory_ca37 {
  strings:
    $key_ca37 = { 9d 45 [2] af 67 [2] a9 52 [2] 87 52 [2] b8 4e }

  condition:
    any of them
}