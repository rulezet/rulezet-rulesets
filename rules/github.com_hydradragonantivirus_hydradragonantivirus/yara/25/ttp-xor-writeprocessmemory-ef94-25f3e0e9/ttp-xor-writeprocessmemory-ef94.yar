rule TTP_XOR_WriteProcessMemory_ef94 {
  strings:
    $key_ef94 = { b8 e6 [2] 8a c4 [2] 8c f1 [2] a2 f1 [2] 9d ed }

  condition:
    any of them
}