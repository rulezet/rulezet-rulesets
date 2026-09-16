rule TTP_XOR_WriteProcessMemory_fde4 {
  strings:
    $key_fde4 = { aa 96 [2] 98 b4 [2] 9e 81 [2] b0 81 [2] 8f 9d }

  condition:
    any of them
}