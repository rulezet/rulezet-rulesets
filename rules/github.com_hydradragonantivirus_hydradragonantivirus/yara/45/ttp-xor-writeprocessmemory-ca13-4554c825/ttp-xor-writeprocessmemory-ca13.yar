rule TTP_XOR_WriteProcessMemory_ca13 {
  strings:
    $key_ca13 = { 9d 61 [2] af 43 [2] a9 76 [2] 87 76 [2] b8 6a }

  condition:
    any of them
}