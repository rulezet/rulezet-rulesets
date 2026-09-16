rule TTP_XOR_WriteProcessMemory_4919 {
  strings:
    $key_4919 = { 1e 6b [2] 2c 49 [2] 2a 7c [2] 04 7c [2] 3b 60 }

  condition:
    any of them
}