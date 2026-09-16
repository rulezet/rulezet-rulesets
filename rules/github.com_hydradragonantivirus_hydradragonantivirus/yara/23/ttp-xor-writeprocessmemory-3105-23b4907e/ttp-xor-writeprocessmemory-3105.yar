rule TTP_XOR_WriteProcessMemory_3105 {
  strings:
    $key_3105 = { 66 77 [2] 54 55 [2] 52 60 [2] 7c 60 [2] 43 7c }

  condition:
    any of them
}