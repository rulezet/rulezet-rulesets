rule TTP_XOR_WriteProcessMemory_ca34 {
  strings:
    $key_ca34 = { 9d 46 [2] af 64 [2] a9 51 [2] 87 51 [2] b8 4d }

  condition:
    any of them
}