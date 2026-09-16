rule TTP_XOR_WriteProcessMemory_ca64 {
  strings:
    $key_ca64 = { 9d 16 [2] af 34 [2] a9 01 [2] 87 01 [2] b8 1d }

  condition:
    any of them
}