rule TTP_XOR_WriteProcessMemory_140d {
  strings:
    $key_140d = { 43 7f [2] 71 5d [2] 77 68 [2] 59 68 [2] 66 74 }

  condition:
    any of them
}