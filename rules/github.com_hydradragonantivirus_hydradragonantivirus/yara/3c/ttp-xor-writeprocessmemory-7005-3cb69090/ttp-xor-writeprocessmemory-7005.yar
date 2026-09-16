rule TTP_XOR_WriteProcessMemory_7005 {
  strings:
    $key_7005 = { 27 77 [2] 15 55 [2] 13 60 [2] 3d 60 [2] 02 7c }

  condition:
    any of them
}