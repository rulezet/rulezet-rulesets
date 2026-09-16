rule TTP_XOR_WriteProcessMemory_ef44 {
  strings:
    $key_ef44 = { b8 36 [2] 8a 14 [2] 8c 21 [2] a2 21 [2] 9d 3d }

  condition:
    any of them
}