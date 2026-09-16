rule TTP_XOR_WriteProcessMemory_b234 {
  strings:
    $key_b234 = { e5 46 [2] d7 64 [2] d1 51 [2] ff 51 [2] c0 4d }

  condition:
    any of them
}