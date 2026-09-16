rule TTP_XOR_WriteProcessMemory_ef60 {
  strings:
    $key_ef60 = { b8 12 [2] 8a 30 [2] 8c 05 [2] a2 05 [2] 9d 19 }

  condition:
    any of them
}