rule TTP_XOR_WriteProcessMemory_c038 {
  strings:
    $key_c038 = { 97 4a [2] a5 68 [2] a3 5d [2] 8d 5d [2] b2 41 }

  condition:
    any of them
}