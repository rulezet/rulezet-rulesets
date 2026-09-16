rule TTP_XOR_WriteProcessMemory_d218 {
  strings:
    $key_d218 = { 85 6a [2] b7 48 [2] b1 7d [2] 9f 7d [2] a0 61 }

  condition:
    any of them
}