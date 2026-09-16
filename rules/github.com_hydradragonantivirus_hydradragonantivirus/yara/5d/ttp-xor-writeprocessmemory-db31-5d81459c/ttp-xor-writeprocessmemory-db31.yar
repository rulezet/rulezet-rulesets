rule TTP_XOR_WriteProcessMemory_db31 {
  strings:
    $key_db31 = { 8c 43 [2] be 61 [2] b8 54 [2] 96 54 [2] a9 48 }

  condition:
    any of them
}