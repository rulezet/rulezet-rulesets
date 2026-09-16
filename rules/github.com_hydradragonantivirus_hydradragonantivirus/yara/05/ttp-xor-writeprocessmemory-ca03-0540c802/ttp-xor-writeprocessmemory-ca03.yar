rule TTP_XOR_WriteProcessMemory_ca03 {
  strings:
    $key_ca03 = { 9d 71 [2] af 53 [2] a9 66 [2] 87 66 [2] b8 7a }

  condition:
    any of them
}