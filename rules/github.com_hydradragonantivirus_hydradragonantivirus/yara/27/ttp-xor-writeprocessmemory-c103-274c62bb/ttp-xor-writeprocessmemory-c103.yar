rule TTP_XOR_WriteProcessMemory_c103 {
  strings:
    $key_c103 = { 96 71 [2] a4 53 [2] a2 66 [2] 8c 66 [2] b3 7a }

  condition:
    any of them
}