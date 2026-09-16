rule TTP_XOR_WriteProcessMemory_319c {
  strings:
    $key_319c = { 66 ee [2] 54 cc [2] 52 f9 [2] 7c f9 [2] 43 e5 }

  condition:
    any of them
}