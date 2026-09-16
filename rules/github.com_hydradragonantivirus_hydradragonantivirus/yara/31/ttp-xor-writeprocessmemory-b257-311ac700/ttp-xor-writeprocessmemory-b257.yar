rule TTP_XOR_WriteProcessMemory_b257 {
  strings:
    $key_b257 = { e5 25 [2] d7 07 [2] d1 32 [2] ff 32 [2] c0 2e }

  condition:
    any of them
}