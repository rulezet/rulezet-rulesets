rule TTP_XOR_WriteProcessMemory_e994 {
  strings:
    $key_e994 = { be e6 [2] 8c c4 [2] 8a f1 [2] a4 f1 [2] 9b ed }

  condition:
    any of them
}