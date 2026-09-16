rule TTP_XOR_WriteProcessMemory_dbe3 {
  strings:
    $key_dbe3 = { 8c 91 [2] be b3 [2] b8 86 [2] 96 86 [2] a9 9a }

  condition:
    any of them
}