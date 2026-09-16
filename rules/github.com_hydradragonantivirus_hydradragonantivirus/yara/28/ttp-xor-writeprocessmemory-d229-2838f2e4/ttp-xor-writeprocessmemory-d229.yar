rule TTP_XOR_WriteProcessMemory_d229 {
  strings:
    $key_d229 = { 85 5b [2] b7 79 [2] b1 4c [2] 9f 4c [2] a0 50 }

  condition:
    any of them
}