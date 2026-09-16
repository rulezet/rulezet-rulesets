rule TTP_XOR_WriteProcessMemory_36b5 {
  strings:
    $key_36b5 = { 61 c7 [2] 53 e5 [2] 55 d0 [2] 7b d0 [2] 44 cc }

  condition:
    any of them
}