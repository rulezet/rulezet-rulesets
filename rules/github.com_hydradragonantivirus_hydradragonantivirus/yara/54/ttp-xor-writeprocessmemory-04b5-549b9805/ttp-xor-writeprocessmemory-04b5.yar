rule TTP_XOR_WriteProcessMemory_04b5 {
  strings:
    $key_04b5 = { 53 c7 [2] 61 e5 [2] 67 d0 [2] 49 d0 [2] 76 cc }

  condition:
    any of them
}