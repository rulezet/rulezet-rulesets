rule TTP_XOR_WriteProcessMemory_d004 {
  strings:
    $key_d004 = { 87 76 [2] b5 54 [2] b3 61 [2] 9d 61 [2] a2 7d }

  condition:
    any of them
}