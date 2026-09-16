rule TTP_XOR_WriteProcessMemory_3144 {
  strings:
    $key_3144 = { 66 36 [2] 54 14 [2] 52 21 [2] 7c 21 [2] 43 3d }

  condition:
    any of them
}