rule TTP_XOR_WriteProcessMemory_34b5 {
  strings:
    $key_34b5 = { 63 c7 [2] 51 e5 [2] 57 d0 [2] 79 d0 [2] 46 cc }

  condition:
    any of them
}