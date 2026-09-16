rule TTP_XOR_WriteProcessMemory_06b5 {
  strings:
    $key_06b5 = { 51 c7 [2] 63 e5 [2] 65 d0 [2] 4b d0 [2] 74 cc }

  condition:
    any of them
}