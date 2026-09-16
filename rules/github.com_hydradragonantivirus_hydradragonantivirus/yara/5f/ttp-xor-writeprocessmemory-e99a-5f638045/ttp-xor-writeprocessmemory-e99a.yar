rule TTP_XOR_WriteProcessMemory_e99a {
  strings:
    $key_e99a = { be e8 [2] 8c ca [2] 8a ff [2] a4 ff [2] 9b e3 }

  condition:
    any of them
}