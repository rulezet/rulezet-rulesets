rule TTP_XOR_WriteProcessMemory_f878 {
  strings:
    $key_f878 = { af 0a [2] 9d 28 [2] 9b 1d [2] b5 1d [2] 8a 01 }

  condition:
    any of them
}