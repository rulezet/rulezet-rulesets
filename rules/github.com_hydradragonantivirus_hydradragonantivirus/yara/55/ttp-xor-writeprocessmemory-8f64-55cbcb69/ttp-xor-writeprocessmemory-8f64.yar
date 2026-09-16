rule TTP_XOR_WriteProcessMemory_8f64 {
  strings:
    $key_8f64 = { d8 16 [2] ea 34 [2] ec 01 [2] c2 01 [2] fd 1d }

  condition:
    any of them
}