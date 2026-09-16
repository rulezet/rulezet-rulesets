rule TTP_XOR_WriteProcessMemory_f804 {
  strings:
    $key_f804 = { af 76 [2] 9d 54 [2] 9b 61 [2] b5 61 [2] 8a 7d }

  condition:
    any of them
}