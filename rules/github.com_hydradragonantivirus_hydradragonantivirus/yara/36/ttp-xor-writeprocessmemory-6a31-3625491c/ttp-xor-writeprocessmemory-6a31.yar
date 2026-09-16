rule TTP_XOR_WriteProcessMemory_6a31 {
  strings:
    $key_6a31 = { 3d 43 [2] 0f 61 [2] 09 54 [2] 27 54 [2] 18 48 }

  condition:
    any of them
}