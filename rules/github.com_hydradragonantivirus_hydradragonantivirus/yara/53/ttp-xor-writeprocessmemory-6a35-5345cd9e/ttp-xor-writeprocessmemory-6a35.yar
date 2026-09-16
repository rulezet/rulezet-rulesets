rule TTP_XOR_WriteProcessMemory_6a35 {
  strings:
    $key_6a35 = { 3d 47 [2] 0f 65 [2] 09 50 [2] 27 50 [2] 18 4c }

  condition:
    any of them
}