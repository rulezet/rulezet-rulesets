rule TTP_XOR_WriteProcessMemory_f813 {
  strings:
    $key_f813 = { af 61 [2] 9d 43 [2] 9b 76 [2] b5 76 [2] 8a 6a }

  condition:
    any of them
}