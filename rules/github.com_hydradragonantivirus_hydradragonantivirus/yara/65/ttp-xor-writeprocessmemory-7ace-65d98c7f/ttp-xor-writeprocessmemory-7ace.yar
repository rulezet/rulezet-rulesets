rule TTP_XOR_WriteProcessMemory_7ace {
  strings:
    $key_7ace = { 2d bc [2] 1f 9e [2] 19 ab [2] 37 ab [2] 08 b7 }

  condition:
    any of them
}