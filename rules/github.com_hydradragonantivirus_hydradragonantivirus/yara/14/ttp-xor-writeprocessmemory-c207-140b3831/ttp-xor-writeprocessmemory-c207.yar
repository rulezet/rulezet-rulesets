rule TTP_XOR_WriteProcessMemory_c207 {
  strings:
    $key_c207 = { 95 75 [2] a7 57 [2] a1 62 [2] 8f 62 [2] b0 7e }

  condition:
    any of them
}