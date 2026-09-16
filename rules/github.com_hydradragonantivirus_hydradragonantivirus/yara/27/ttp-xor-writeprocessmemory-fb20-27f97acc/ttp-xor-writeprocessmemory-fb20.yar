rule TTP_XOR_WriteProcessMemory_fb20 {
  strings:
    $key_fb20 = { ac 52 [2] 9e 70 [2] 98 45 [2] b6 45 [2] 89 59 }

  condition:
    any of them
}