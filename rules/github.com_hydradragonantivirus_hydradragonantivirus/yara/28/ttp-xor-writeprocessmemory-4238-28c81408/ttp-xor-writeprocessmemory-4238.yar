rule TTP_XOR_WriteProcessMemory_4238 {
  strings:
    $key_4238 = { 15 4a [2] 27 68 [2] 21 5d [2] 0f 5d [2] 30 41 }

  condition:
    any of them
}