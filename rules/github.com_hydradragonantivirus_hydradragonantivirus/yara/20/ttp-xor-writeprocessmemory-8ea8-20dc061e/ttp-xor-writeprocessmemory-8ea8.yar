rule TTP_XOR_WriteProcessMemory_8ea8 {
  strings:
    $key_8ea8 = { d9 da [2] eb f8 [2] ed cd [2] c3 cd [2] fc d1 }

  condition:
    any of them
}