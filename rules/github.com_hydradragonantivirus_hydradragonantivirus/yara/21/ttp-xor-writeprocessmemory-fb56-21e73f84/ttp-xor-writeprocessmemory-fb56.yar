rule TTP_XOR_WriteProcessMemory_fb56 {
  strings:
    $key_fb56 = { ac 24 [2] 9e 06 [2] 98 33 [2] b6 33 [2] 89 2f }

  condition:
    any of them
}