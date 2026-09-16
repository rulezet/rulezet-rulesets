rule TTP_XOR_WriteProcessMemory_6ac8 {
  strings:
    $key_6ac8 = { 3d ba [2] 0f 98 [2] 09 ad [2] 27 ad [2] 18 b1 }

  condition:
    any of them
}