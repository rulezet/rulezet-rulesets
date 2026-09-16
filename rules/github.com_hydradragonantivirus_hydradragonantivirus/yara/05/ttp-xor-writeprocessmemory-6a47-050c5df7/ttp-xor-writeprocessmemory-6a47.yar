rule TTP_XOR_WriteProcessMemory_6a47 {
  strings:
    $key_6a47 = { 3d 35 [2] 0f 17 [2] 09 22 [2] 27 22 [2] 18 3e }

  condition:
    any of them
}