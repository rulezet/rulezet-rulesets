rule TTP_XOR_WriteProcessMemory_6ace {
  strings:
    $key_6ace = { 3d bc [2] 0f 9e [2] 09 ab [2] 27 ab [2] 18 b7 }

  condition:
    any of them
}