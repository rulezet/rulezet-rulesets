rule TTP_XOR_WriteProcessMemory_32b5 {
  strings:
    $key_32b5 = { 65 c7 [2] 57 e5 [2] 51 d0 [2] 7f d0 [2] 40 cc }

  condition:
    any of them
}