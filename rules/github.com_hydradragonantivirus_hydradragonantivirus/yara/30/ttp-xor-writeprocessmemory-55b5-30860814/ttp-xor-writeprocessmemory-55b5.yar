rule TTP_XOR_WriteProcessMemory_55b5 {
  strings:
    $key_55b5 = { 02 c7 [2] 30 e5 [2] 36 d0 [2] 18 d0 [2] 27 cc }

  condition:
    any of them
}