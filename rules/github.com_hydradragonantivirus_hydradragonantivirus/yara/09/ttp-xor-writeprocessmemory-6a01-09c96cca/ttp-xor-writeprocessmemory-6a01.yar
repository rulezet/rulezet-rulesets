rule TTP_XOR_WriteProcessMemory_6a01 {
  strings:
    $key_6a01 = { 3d 73 [2] 0f 51 [2] 09 64 [2] 27 64 [2] 18 78 }

  condition:
    any of them
}