rule TTP_XOR_WriteProcessMemory_c227 {
  strings:
    $key_c227 = { 95 55 [2] a7 77 [2] a1 42 [2] 8f 42 [2] b0 5e }

  condition:
    any of them
}