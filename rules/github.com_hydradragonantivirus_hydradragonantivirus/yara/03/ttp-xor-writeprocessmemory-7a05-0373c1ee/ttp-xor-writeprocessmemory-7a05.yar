rule TTP_XOR_WriteProcessMemory_7a05 {
  strings:
    $key_7a05 = { 2d 77 [2] 1f 55 [2] 19 60 [2] 37 60 [2] 08 7c }

  condition:
    any of them
}