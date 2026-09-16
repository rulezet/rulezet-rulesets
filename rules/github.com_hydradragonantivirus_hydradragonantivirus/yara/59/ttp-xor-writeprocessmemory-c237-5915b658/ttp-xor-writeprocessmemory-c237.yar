rule TTP_XOR_WriteProcessMemory_c237 {
  strings:
    $key_c237 = { 95 45 [2] a7 67 [2] a1 52 [2] 8f 52 [2] b0 4e }

  condition:
    any of them
}