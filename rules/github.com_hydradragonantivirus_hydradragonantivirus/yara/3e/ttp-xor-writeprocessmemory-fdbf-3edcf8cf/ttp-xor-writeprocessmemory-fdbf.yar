rule TTP_XOR_WriteProcessMemory_fdbf {
  strings:
    $key_fdbf = { aa cd [2] 98 ef [2] 9e da [2] b0 da [2] 8f c6 }

  condition:
    any of them
}