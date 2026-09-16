rule TTP_XOR_WriteProcessMemory_fbbf {
  strings:
    $key_fbbf = { ac cd [2] 9e ef [2] 98 da [2] b6 da [2] 89 c6 }

  condition:
    any of them
}