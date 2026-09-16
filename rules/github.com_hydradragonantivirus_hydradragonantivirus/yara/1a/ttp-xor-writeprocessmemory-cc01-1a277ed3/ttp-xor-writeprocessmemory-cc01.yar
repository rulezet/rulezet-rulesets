rule TTP_XOR_WriteProcessMemory_cc01 {
  strings:
    $key_cc01 = { 9b 73 [2] a9 51 [2] af 64 [2] 81 64 [2] be 78 }

  condition:
    any of them
}