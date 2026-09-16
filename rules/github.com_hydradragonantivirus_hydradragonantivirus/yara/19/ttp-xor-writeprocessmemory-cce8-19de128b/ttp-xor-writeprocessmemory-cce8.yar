rule TTP_XOR_WriteProcessMemory_cce8 {
  strings:
    $key_cce8 = { 9b 9a [2] a9 b8 [2] af 8d [2] 81 8d [2] be 91 }

  condition:
    any of them
}