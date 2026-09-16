rule TTP_XOR_WriteProcessMemory_70c7 {
  strings:
    $key_70c7 = { 27 b5 [2] 15 97 [2] 13 a2 [2] 3d a2 [2] 02 be }

  condition:
    any of them
}