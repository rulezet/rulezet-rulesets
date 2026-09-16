rule TTP_XOR_WriteProcessMemory_6a15 {
  strings:
    $key_6a15 = { 3d 67 [2] 0f 45 [2] 09 70 [2] 27 70 [2] 18 6c }

  condition:
    any of them
}