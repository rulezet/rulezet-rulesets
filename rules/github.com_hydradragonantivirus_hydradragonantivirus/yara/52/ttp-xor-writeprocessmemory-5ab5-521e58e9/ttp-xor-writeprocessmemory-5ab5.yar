rule TTP_XOR_WriteProcessMemory_5ab5 {
  strings:
    $key_5ab5 = { 0d c7 [2] 3f e5 [2] 39 d0 [2] 17 d0 [2] 28 cc }

  condition:
    any of them
}