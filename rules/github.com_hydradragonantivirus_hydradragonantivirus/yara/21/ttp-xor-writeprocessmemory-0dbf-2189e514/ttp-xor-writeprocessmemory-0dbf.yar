rule TTP_XOR_WriteProcessMemory_0dbf {
  strings:
    $key_0dbf = { 5a cd [2] 68 ef [2] 6e da [2] 40 da [2] 7f c6 }

  condition:
    any of them
}