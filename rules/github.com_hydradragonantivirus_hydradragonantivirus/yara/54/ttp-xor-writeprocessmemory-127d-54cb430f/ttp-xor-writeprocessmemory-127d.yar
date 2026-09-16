rule TTP_XOR_WriteProcessMemory_127d {
  strings:
    $key_127d = { 45 0f [2] 77 2d [2] 71 18 [2] 5f 18 [2] 60 04 }

  condition:
    any of them
}