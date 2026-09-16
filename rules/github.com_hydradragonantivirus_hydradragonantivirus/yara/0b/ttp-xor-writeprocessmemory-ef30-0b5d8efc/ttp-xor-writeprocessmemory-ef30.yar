rule TTP_XOR_WriteProcessMemory_ef30 {
  strings:
    $key_ef30 = { b8 42 [2] 8a 60 [2] 8c 55 [2] a2 55 [2] 9d 49 }

  condition:
    any of them
}