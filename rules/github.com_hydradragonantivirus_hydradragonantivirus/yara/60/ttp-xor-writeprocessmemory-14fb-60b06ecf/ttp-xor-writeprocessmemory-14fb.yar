rule TTP_XOR_WriteProcessMemory_14fb {
  strings:
    $key_14fb = { 43 89 [2] 71 ab [2] 77 9e [2] 59 9e [2] 66 82 }

  condition:
    any of them
}