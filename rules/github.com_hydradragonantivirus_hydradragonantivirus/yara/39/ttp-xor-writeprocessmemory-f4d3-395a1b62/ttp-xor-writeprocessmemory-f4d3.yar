rule TTP_XOR_WriteProcessMemory_f4d3 {
  strings:
    $key_f4d3 = { a3 a1 [2] 91 83 [2] 97 b6 [2] b9 b6 [2] 86 aa }

  condition:
    any of them
}