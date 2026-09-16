rule TTP_XOR_WriteProcessMemory_cae4 {
  strings:
    $key_cae4 = { 9d 96 [2] af b4 [2] a9 81 [2] 87 81 [2] b8 9d }

  condition:
    any of them
}