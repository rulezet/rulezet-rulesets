rule TTP_XOR_WriteProcessMemory_fb59 {
  strings:
    $key_fb59 = { ac 2b [2] 9e 09 [2] 98 3c [2] b6 3c [2] 89 20 }

  condition:
    any of them
}