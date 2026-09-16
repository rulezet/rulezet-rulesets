rule TTP_XOR_WriteProcessMemory_d414 {
  strings:
    $key_d414 = { 83 66 [2] b1 44 [2] b7 71 [2] 99 71 [2] a6 6d }

  condition:
    any of them
}