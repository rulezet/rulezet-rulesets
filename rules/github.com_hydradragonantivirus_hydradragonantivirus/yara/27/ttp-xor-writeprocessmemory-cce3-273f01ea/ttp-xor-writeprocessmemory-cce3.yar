rule TTP_XOR_WriteProcessMemory_cce3 {
  strings:
    $key_cce3 = { 9b 91 [2] a9 b3 [2] af 86 [2] 81 86 [2] be 9a }

  condition:
    any of them
}