rule TTP_XOR_WriteProcessMemory_6ac9 {
  strings:
    $key_6ac9 = { 3d bb [2] 0f 99 [2] 09 ac [2] 27 ac [2] 18 b0 }

  condition:
    any of them
}