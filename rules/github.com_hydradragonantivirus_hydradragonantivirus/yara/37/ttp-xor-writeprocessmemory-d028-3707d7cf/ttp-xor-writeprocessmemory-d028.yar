rule TTP_XOR_WriteProcessMemory_d028 {
  strings:
    $key_d028 = { 87 5a [2] b5 78 [2] b3 4d [2] 9d 4d [2] a2 51 }

  condition:
    any of them
}