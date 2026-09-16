rule TTP_XOR_WriteProcessMemory_fb14 {
  strings:
    $key_fb14 = { ac 66 [2] 9e 44 [2] 98 71 [2] b6 71 [2] 89 6d }

  condition:
    any of them
}