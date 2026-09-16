rule TTP_XOR_WriteProcessMemory_cc47 {
  strings:
    $key_cc47 = { 9b 35 [2] a9 17 [2] af 22 [2] 81 22 [2] be 3e }

  condition:
    any of them
}