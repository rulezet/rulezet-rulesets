rule TTP_XOR_WriteProcessMemory_d786 {
  strings:
    $key_d786 = { 80 f4 [2] b2 d6 [2] b4 e3 [2] 9a e3 [2] a5 ff }

  condition:
    any of them
}