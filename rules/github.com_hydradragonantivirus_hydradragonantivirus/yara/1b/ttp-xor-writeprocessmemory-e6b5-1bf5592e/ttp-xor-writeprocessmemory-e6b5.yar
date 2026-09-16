rule TTP_XOR_WriteProcessMemory_e6b5 {
  strings:
    $key_e6b5 = { b1 c7 [2] 83 e5 [2] 85 d0 [2] ab d0 [2] 94 cc }

  condition:
    any of them
}