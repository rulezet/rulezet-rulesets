rule TTP_XOR_WriteProcessMemory_cc71 {
  strings:
    $key_cc71 = { 9b 03 [2] a9 21 [2] af 14 [2] 81 14 [2] be 08 }

  condition:
    any of them
}