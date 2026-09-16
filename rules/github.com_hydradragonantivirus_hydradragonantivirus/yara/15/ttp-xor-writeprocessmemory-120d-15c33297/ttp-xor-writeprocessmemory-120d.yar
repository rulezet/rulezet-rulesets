rule TTP_XOR_WriteProcessMemory_120d {
  strings:
    $key_120d = { 45 7f [2] 77 5d [2] 71 68 [2] 5f 68 [2] 60 74 }

  condition:
    any of them
}