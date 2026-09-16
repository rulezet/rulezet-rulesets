rule TTP_XOR_WriteProcessMemory_e719 {
  strings:
    $key_e719 = { b0 6b [2] 82 49 [2] 84 7c [2] aa 7c [2] 95 60 }

  condition:
    any of them
}